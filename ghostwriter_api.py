from __future__ import annotations

import json
import math
import ssl
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import urljoin
from urllib.parse import urlparse


FINDING_FIELDS = (
    "id",
    "severity",
    "cvss_score",
    "cvss_vector",
    "finding_type",
    "title",
    "description",
    "impact",
    "mitigation",
    "replication_steps",
    "host_detection_techniques",
    "network_detection_techniques",
    "references",
    "finding_guidance",
    "tags",
    "extra_fields",
)

SYNC_PREFLIGHT_QUERY_FIELDS = {"finding", "findingSeverity", "findingType", "tags"}
SYNC_PREFLIGHT_MUTATION_FIELDS = {"delete_finding_by_pk", "insert_finding_one", "setTags"}


class GhostwriterApiError(RuntimeError):
    """Raised when Ghostwriter API interaction cannot complete safely."""


@dataclass(frozen=True)
class GhostwriterServerConfig:
    side: str
    name: str
    graphql_url: str
    bearer_token: str
    timeout_seconds: float = 30.0
    verify_tls: bool = True
    strict_x509_verification: bool = True
    rate_limit_per_second: float = 1.0

    @property
    def is_configured(self) -> bool:
        return bool(self.graphql_url and self.bearer_token)


@dataclass
class SyncEvent:
    stage: str
    message: str
    complete: int = 0
    total: int = 0
    status: str = "running"


class RateLimiter:
    """Simple per-client rate limiter to avoid overwhelming Ghostwriter."""

    def __init__(self, requests_per_second: float):
        self.requests_per_second = max(float(requests_per_second or 1.0), 0.1)
        self._last_request_at = 0.0

    def wait(self) -> None:
        interval = 1.0 / self.requests_per_second
        elapsed = time.monotonic() - self._last_request_at
        if elapsed < interval:
            time.sleep(interval - elapsed)
        self._last_request_at = time.monotonic()


class GhostwriterGraphQLClient:
    """Minimal stdlib GraphQL client for Ghostwriter's Hasura endpoint."""

    def __init__(self, server: GhostwriterServerConfig):
        self.server = server
        self.rate_limiter = RateLimiter(server.rate_limit_per_second)

    def execute(self, query: str, variables: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        self.rate_limiter.wait()
        payload = json.dumps({"query": query, "variables": variables or {}}).encode("utf-8")
        request = urllib.request.Request(
            self.server.graphql_url,
            data=payload,
            headers={
                "Authorization": f"Bearer {self.server.bearer_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        try:
            ssl_context = _ssl_context_for_server(self.server)
            with urllib.request.urlopen(request, timeout=self.server.timeout_seconds, context=ssl_context) as response:
                response_body = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise GhostwriterApiError(_redact(f"Ghostwriter HTTP {exc.code}: {detail}", self.server)) from exc
        except urllib.error.URLError as exc:
            raise GhostwriterApiError(_redact(f"Ghostwriter connection failed: {exc}", self.server)) from exc

        try:
            data = json.loads(response_body)
        except json.JSONDecodeError as exc:
            raise GhostwriterApiError("Ghostwriter returned invalid JSON.") from exc
        if data.get("errors"):
            raise GhostwriterApiError(_redact(f"Ghostwriter GraphQL error: {data['errors']}", self.server))
        if "data" not in data:
            raise GhostwriterApiError("Ghostwriter response did not include a data object.")
        return data["data"]


class GhostwriterApi:
    """High-level API operations for finding-library synchronisation."""

    def __init__(
        self,
        server: GhostwriterServerConfig,
        client: Optional[Any] = None,
        progress: Optional[Callable[[SyncEvent], None]] = None,
    ):
        self.server = server
        self.client = client or GhostwriterGraphQLClient(server)
        self.progress = progress or (lambda event: None)

    def fetch_findings(self) -> list[dict[str, Any]]:
        query = """
        query FetchFindings($limit: Int!, $offset: Int!) {
          finding(limit: $limit, offset: $offset, order_by: {id: asc}) {
            id
            title
            cvssScore
            cvssVector
            description
            impact
            mitigation
            replication_steps
            hostDetectionTechniques
            networkDetectionTechniques
            references
            findingGuidance
            extraFields
            severity { severity }
            type { findingType }
          }
        }
        """
        records: list[dict[str, Any]] = []
        offset = 0
        limit = 100
        while True:
            self.progress(SyncEvent("fetch", f"Fetching {self.server.name}", len(records), 0))
            data = self.client.execute(query, {"limit": limit, "offset": offset})
            batch = data.get("finding") or []
            if not batch:
                break
            for item in batch:
                record = self._api_record_to_ghostmerge(item)
                record["tags"] = ", ".join(self.fetch_tags(int(item["id"])))
                records.append(record)
            if len(batch) < limit:
                break
            offset += limit
        self.progress(SyncEvent("fetch", f"Fetched {len(records)} findings from {self.server.name}", len(records), len(records), "done"))
        return records

    def fetch_tags(self, finding_id: int) -> list[str]:
        query = """
        query Tags($id: bigint!) {
          tags(model: "finding", id: $id) { tags }
        }
        """
        data = self.client.execute(query, {"id": finding_id})
        return list((data.get("tags") or {}).get("tags") or [])

    def create_backup(self, backup_root: Path) -> Path:
        raw_records = self.fetch_raw_findings_with_tags()
        normalised_records = [self._api_record_to_ghostmerge(item["record"]) | {"tags": ", ".join(item["tags"])} for item in raw_records]
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup_dir = backup_root / self.server.side
        backup_dir.mkdir(parents=True, exist_ok=True)
        backup_path = backup_dir / f"{timestamp}-{_slug(self.server.name)}-{uuid.uuid4().hex[:8]}.json"
        backup_data = {
            "server_side": self.server.side,
            "server_name": self.server.name,
            "graphql_url": self.server.graphql_url,
            "created_at": timestamp,
            "record_count": len(raw_records),
            "raw_records": raw_records,
            "normalised_records": normalised_records,
        }
        with backup_path.open("x", encoding="utf-8") as handle:
            json.dump(backup_data, handle, indent=2)
        verify_backup(backup_path)
        self.progress(SyncEvent("backup", f"Backup written for {self.server.name}", len(raw_records), len(raw_records), "done"))
        return backup_path

    def fetch_raw_findings_with_tags(self) -> list[dict[str, Any]]:
        query = """
        query FetchRawFindings($limit: Int!, $offset: Int!) {
          finding(limit: $limit, offset: $offset, order_by: {id: asc}) {
            id
            title
            cvssScore
            cvssVector
            description
            impact
            mitigation
            replication_steps
            hostDetectionTechniques
            networkDetectionTechniques
            references
            findingGuidance
            extraFields
            severity { id severity }
            type { id findingType }
          }
        }
        """
        raw_records: list[dict[str, Any]] = []
        offset = 0
        limit = 100
        while True:
            data = self.client.execute(query, {"limit": limit, "offset": offset})
            batch = data.get("finding") or []
            if not batch:
                break
            for item in batch:
                raw_records.append({"record": item, "tags": self.fetch_tags(int(item["id"]))})
            if len(batch) < limit:
                break
            offset += limit
        return raw_records

    def preflight_sync_permissions(self) -> None:
        """Check the configured token can see every GraphQL field live sync requires."""
        query = """
        query SyncPreflight {
          __schema {
            queryType { fields { name } }
            mutationType { fields { name } }
          }
        }
        """
        try:
            data = self.client.execute(query)
        except GhostwriterApiError as exc:
            detail = _redact(str(exc), self.server)
            raise GhostwriterApiError(f"Ghostwriter API sync preflight failed for {self.server.name}: {detail}") from exc

        schema = data.get("__schema") or {}
        query_fields = _schema_field_names(((schema.get("queryType") or {}).get("fields") or []))
        mutation_fields = _schema_field_names(((schema.get("mutationType") or {}).get("fields") or []))
        missing_query_fields = sorted(SYNC_PREFLIGHT_QUERY_FIELDS - query_fields)
        missing_mutation_fields = sorted(SYNC_PREFLIGHT_MUTATION_FIELDS - mutation_fields)
        if missing_query_fields or missing_mutation_fields:
            details = []
            if missing_query_fields:
                details.append(f"missing query fields: {', '.join(missing_query_fields)}")
            if missing_mutation_fields:
                details.append(f"missing mutation fields: {', '.join(missing_mutation_fields)}")
            raise GhostwriterApiError(
                "Ghostwriter API sync preflight failed for "
                f"{self.server.name}; {'; '.join(details)}. "
                "Use a Ghostwriter API token or service token with read/write access to Finding Templates and tags."
            )

    def replace_all_findings(self, records: list[dict[str, Any]], backup_root: Path) -> Path:
        self.preflight_sync_permissions()
        lookups = self.fetch_lookup_ids()
        prepared_records = self.prepare_records_for_reload(records, lookups)
        backup_path = self.create_backup(backup_root)
        existing_ids = self.fetch_finding_ids()
        for index, finding_id in enumerate(existing_ids, start=1):
            self.progress(SyncEvent("delete", f"Deleting existing findings from {self.server.name}", index, len(existing_ids)))
            self.delete_finding(finding_id)
        for index, prepared in enumerate(prepared_records, start=1):
            self.progress(SyncEvent("create", f"Creating reviewed findings on {self.server.name}", index, len(records)))
            created_id = self.create_prepared_finding(prepared["api_record"])
            self.set_tags(created_id, prepared["tags"])
        self.progress(SyncEvent("complete", f"Sync complete for {self.server.name}", len(records), len(records), "done"))
        return backup_path

    def prepare_records_for_reload(
        self,
        records: list[dict[str, Any]],
        lookups: dict[str, dict[str, int]],
    ) -> list[dict[str, Any]]:
        prepared_records = []
        for index, record in enumerate(records, start=1):
            try:
                api_record = ghostmerge_record_to_api_input(record, lookups)
                tags = _split_tags(record.get("tags"))
            except Exception as exc:
                title = record.get("title") or f"record {index}"
                raise GhostwriterApiError(f"Cannot prepare Finding Template {index} ({title}) for reload: {exc}") from exc
            prepared_records.append({"api_record": api_record, "tags": tags})
        return prepared_records

    def fetch_finding_ids(self) -> list[int]:
        query = """
        query FindingIds {
          finding(order_by: {id: asc}) { id }
        }
        """
        data = self.client.execute(query)
        return [int(item["id"]) for item in data.get("finding", [])]

    def delete_finding(self, finding_id: int) -> None:
        mutation = """
        mutation DeleteFinding($id: bigint!) {
          delete_finding_by_pk(id: $id) { id }
        }
        """
        self.client.execute(mutation, {"id": finding_id})

    def fetch_lookup_ids(self) -> dict[str, dict[str, int]]:
        query = """
        query FindingLookups {
          findingSeverity { id severity }
          findingType { id findingType }
        }
        """
        data = self.client.execute(query)
        return {
            "severity": {item["severity"]: int(item["id"]) for item in data.get("findingSeverity", [])},
            "finding_type": {item["findingType"]: int(item["id"]) for item in data.get("findingType", [])},
        }

    def create_finding(self, record: dict[str, Any], lookups: dict[str, dict[str, int]]) -> int:
        return self.create_prepared_finding(ghostmerge_record_to_api_input(record, lookups))

    def create_prepared_finding(self, api_record: dict[str, Any]) -> int:
        mutation = """
        mutation CreateFinding($object: finding_insert_input!) {
          insert_finding_one(object: $object) { id }
        }
        """
        data = self.client.execute(mutation, {"object": api_record})
        created = data.get("insert_finding_one")
        if not created:
            raise GhostwriterApiError("Ghostwriter did not return the created finding ID.")
        return int(created["id"])

    def set_tags(self, finding_id: int, tags: list[str]) -> None:
        mutation = """
        mutation SetFindingTags($id: bigint!, $tags: [String!]!) {
          setTags(model: "finding", id: $id, tags: $tags) { tags }
        }
        """
        self.client.execute(mutation, {"id": finding_id, "tags": tags})

    def restore_backup_record(self, backup_record: dict[str, Any]) -> int:
        lookups = self.fetch_lookup_ids()
        record = backup_record.get("normalised_record") or backup_record
        created_id = self.create_finding(record, lookups)
        self.set_tags(created_id, _split_tags(record.get("tags")))
        return created_id

    def _api_record_to_ghostmerge(self, record: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": str(record.get("id", "")),
            "severity": (record.get("severity") or {}).get("severity"),
            "cvss_score": "" if record.get("cvssScore") is None else str(record.get("cvssScore")),
            "cvss_vector": record.get("cvssVector") or "",
            "finding_type": (record.get("type") or {}).get("findingType"),
            "title": record.get("title") or "",
            "description": record.get("description") or "",
            "impact": record.get("impact") or "",
            "mitigation": record.get("mitigation") or "",
            "replication_steps": record.get("replication_steps") or "",
            "host_detection_techniques": record.get("hostDetectionTechniques") or "",
            "network_detection_techniques": record.get("networkDetectionTechniques") or "",
            "references": record.get("references") or "",
            "finding_guidance": record.get("findingGuidance") or "",
            "tags": "",
            "extra_fields": record.get("extraFields") or {},
        }


def ghostmerge_record_to_api_input(record: dict[str, Any], lookups: dict[str, dict[str, int]]) -> dict[str, Any]:
    severity = str(record.get("severity") or "")
    finding_type = str(record.get("finding_type") or "")
    try:
        severity_id = lookups["severity"][severity]
        finding_type_id = lookups["finding_type"][finding_type]
    except KeyError as exc:
        raise GhostwriterApiError(f"Missing Ghostwriter lookup for {exc.args[0]!r}.") from exc
    return {
        "title": record.get("title") or "",
        "severityId": severity_id,
        "findingTypeId": finding_type_id,
        "cvssScore": _optional_float(record.get("cvss_score")),
        "cvssVector": record.get("cvss_vector") or "",
        "description": record.get("description") or "",
        "impact": record.get("impact") or "",
        "mitigation": record.get("mitigation") or "",
        "replication_steps": record.get("replication_steps") or "",
        "hostDetectionTechniques": record.get("host_detection_techniques") or "",
        "networkDetectionTechniques": record.get("network_detection_techniques") or "",
        "references": record.get("references") or "",
        "findingGuidance": record.get("finding_guidance") or "",
        "extraFields": _extra_fields(record.get("extra_fields")),
    }


def load_server_configs(config: dict[str, Any]) -> dict[str, Optional[GhostwriterServerConfig]]:
    api_config = config.get("ghostwriter_api", {})
    servers = api_config.get("servers", {})
    default_rate = float(api_config.get("default_rate_limit_per_second", 1.0))
    parsed: dict[str, Optional[GhostwriterServerConfig]] = {}
    for side in ("left", "right"):
        server = servers.get(side, {})
        graphql_url = str(server.get("graphql_url") or "")
        graphql_endpoint = str(server.get("graphql_endpoint") or "")
        base_url = str(server.get("base_url") or "")
        if not graphql_url:
            graphql_url = _resolve_graphql_endpoint(base_url, graphql_endpoint)
        enabled = bool(server.get("enabled", False))
        token = str(server.get("bearer_token") or "")
        if not enabled or not graphql_url or not token:
            parsed[side] = None
            continue
        parsed[side] = GhostwriterServerConfig(
            side=side,
            name=str(server.get("name") or side.title()),
            graphql_url=graphql_url,
            bearer_token=token,
            timeout_seconds=float(server.get("timeout_seconds", 30.0)),
            verify_tls=bool(server.get("verify_tls", True)),
            strict_x509_verification=bool(server.get("strict_x509_verification", True)),
            rate_limit_per_second=float(server.get("rate_limit_per_second", default_rate)),
        )
    return parsed


def _resolve_graphql_endpoint(base_url: str, graphql_endpoint: str) -> str:
    if graphql_endpoint and urlparse(graphql_endpoint).scheme:
        return graphql_endpoint
    if base_url:
        endpoint = graphql_endpoint or "/v1/graphql"
        return urljoin(base_url.rstrip("/") + "/", endpoint.lstrip("/"))
    return ""


def configured_server_summary(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    servers = load_server_configs(config)
    return {
        side: {
            "configured": server is not None,
            "name": server.name if server else side.title(),
            "rate_limit_per_second": server.rate_limit_per_second if server else None,
        }
        for side, server in servers.items()
    }


def backup_root_from_config(config: dict[str, Any]) -> Path:
    api_config = config.get("ghostwriter_api", {})
    root = Path(api_config.get("backup_dir") or "ghostmerge_api_backups")
    if not root.is_absolute():
        root = Path(config.get("script_dir", Path.cwd())) / root
    return root


def verify_backup(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data.get("raw_records"), list):
        raise GhostwriterApiError("Backup does not contain raw_records.")
    if not isinstance(data.get("normalised_records"), list):
        raise GhostwriterApiError("Backup does not contain normalised_records.")
    if data.get("record_count") != len(data["raw_records"]):
        raise GhostwriterApiError("Backup record count does not match its contents.")
    if len(data["normalised_records"]) != len(data["raw_records"]):
        raise GhostwriterApiError("Backup raw and normalised record counts do not match.")
    return data


def list_backups(backup_root: Path) -> list[dict[str, Any]]:
    backups = []
    if not backup_root.exists():
        return backups
    for path in sorted(backup_root.glob("*/*.json"), reverse=True):
        try:
            data = verify_backup(path)
        except Exception:
            continue
        backups.append(
            {
                "path": str(path),
                "filename": path.name,
                "side": data.get("server_side"),
                "server_name": data.get("server_name"),
                "created_at": data.get("created_at"),
                "record_count": data.get("record_count"),
            }
        )
    return backups


def load_backup_record(path: Path, index: int) -> dict[str, Any]:
    data = verify_backup(path)
    records = data["normalised_records"]
    if index < 0 or index >= len(records):
        raise GhostwriterApiError("Backup record index is out of range.")
    return {
        "backup": data,
        "normalised_record": records[index],
        "raw_record": data["raw_records"][index],
        "index": index,
    }


def _optional_float(value: Any) -> Optional[float]:
    if value in (None, ""):
        return None
    number = float(value)
    if not math.isfinite(number):
        raise GhostwriterApiError("cvss_score must be finite.")
    if number < 0.0 or number > 10.0:
        raise GhostwriterApiError("cvss_score must be between 0.0 and 10.0.")
    return number


def _extra_fields(value: Any) -> dict[str, Any]:
    if value in (None, ""):
        return {}
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        parsed = json.loads(value)
        if not isinstance(parsed, dict):
            raise GhostwriterApiError("extra_fields must be a JSON object.")
        return parsed
    raise GhostwriterApiError("extra_fields must be a JSON object.")


def _split_tags(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [item.strip() for item in str(value).split(",") if item.strip()]


def _ssl_context_for_server(server: GhostwriterServerConfig):
    if not server.verify_tls:
        return ssl._create_unverified_context()
    if server.strict_x509_verification:
        return None
    context = ssl.create_default_context()
    if hasattr(ssl, "VERIFY_X509_STRICT"):
        context.verify_flags &= ~ssl.VERIFY_X509_STRICT
    return context


def _schema_field_names(fields: list[dict[str, Any]]) -> set[str]:
    return {str(field.get("name") or "") for field in fields if field.get("name")}


def _slug(value: str) -> str:
    slug = "".join(char.lower() if char.isalnum() else "-" for char in value).strip("-")
    return slug or "server"


def _redact(message: str, server: GhostwriterServerConfig) -> str:
    if server.bearer_token:
        return message.replace(server.bearer_token, "[REDACTED]")
    return message
