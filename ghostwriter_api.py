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

from utils import (
    KNOWN_EXTRA_FIELD_TYPES,
    apply_configured_extra_fields_normalisation,
    apply_extra_fields_key_migrations,
    log,
)


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

OBSERVATION_FIELDS = ("id", "title", "description", "tags", "extra_fields")

SYNC_PREFLIGHT_QUERY_FIELDS = {"finding", "findingSeverity", "findingType", "observation", "tags"}
SYNC_PREFLIGHT_MUTATION_FIELDS = {
    "delete_finding_by_pk",
    "insert_finding_one",
    "delete_observation_by_pk",
    "insert_observation_one",
    "setTags",
}
GHOSTMERGE_LAST_SYNCED_AT_FIELD = "ghostmerge_last_synced_at"
SYNC_VALIDATION_MODES = frozenset({"full", "sample", "none"})
MAX_SYNC_BATCH_SIZE = 100


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
    rate_limit_per_second: float = 0.2
    sync_batch_size: int = 25
    sync_validation_mode: str = "full"
    sync_validation_sample_size: int = 10

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
    backup_path: Optional[str] = None


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
    """High-level API operations for Ghostwriter template-library synchronisation."""

    def __init__(
        self,
        server: GhostwriterServerConfig,
        client: Optional[Any] = None,
        progress: Optional[Callable[[SyncEvent], None]] = None,
    ):
        self.server = server
        self.client = client or GhostwriterGraphQLClient(server)
        self.progress = progress or (lambda event: None)
        self._extra_field_specs: Optional[dict[str, dict[str, str]]] = None

    def fetch_extra_field_specs(self) -> dict[str, dict[str, str]]:
        """Fetch and cache extra-field types for supported template models."""
        if self._extra_field_specs is not None:
            return self._extra_field_specs

        query = """
        query FetchExtraFieldSpecs {
          extraFieldSpec(
            where: {
              targetModel: {
                _in: ["reporting.Finding", "reporting.Observation"]
              }
            }
            order_by: {id: asc}
          ) {
            targetModel
            internalName
            type
          }
        }
        """
        specs: dict[str, dict[str, str]] = {
            "finding": {},
            "observation": {},
        }
        try:
            data = self.client.execute(query)
        except GhostwriterApiError as exc:
            log(
                "WARN",
                f"Could not fetch extra-field specifications from {self.server.name}; "
                f"using conservative extra-field code repair ({exc}).",
                prefix="API",
            )
            self._extra_field_specs = specs
            return specs

        target_types = {
            "reporting.Finding": "finding",
            "reporting.Observation": "observation",
        }
        ambiguous: set[tuple[str, str]] = set()
        for item in data.get("extraFieldSpec") or []:
            if not isinstance(item, dict):
                log("WARN", "Ignored malformed Ghostwriter extra-field specification.", prefix="API")
                continue

            template_type = target_types.get(str(item.get("targetModel") or ""))
            internal_name = str(item.get("internalName") or "").strip()
            field_type = str(item.get("type") or "").strip()
            if template_type is None or not internal_name or not field_type:
                log("WARN", "Ignored incomplete Ghostwriter extra-field specification.", prefix="API")
                continue

            identity = (template_type, internal_name)
            if identity in ambiguous:
                continue
            existing_type = specs[template_type].get(internal_name)
            if existing_type is not None and existing_type != field_type:
                specs[template_type].pop(internal_name, None)
                ambiguous.add(identity)
                log(
                    "WARN",
                    f'Conflicting Ghostwriter types for extra field "{internal_name}" '
                    f"on {template_type} templates; using conservative code repair.",
                    prefix="API",
                )
                continue
            if field_type not in KNOWN_EXTRA_FIELD_TYPES:
                log(
                    "WARN",
                    f'Unknown Ghostwriter type "{field_type}" for extra field '
                    f'"{internal_name}"; using conservative code repair.',
                    prefix="API",
                )
            specs[template_type][internal_name] = field_type

        self._extra_field_specs = specs
        return specs

    def fetch_findings(self) -> list[dict[str, Any]]:
        field_types = self.fetch_extra_field_specs()["finding"]
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
            tags_by_id = self.fetch_tags_batch(
                [int(item["id"]) for item in batch],
                model="finding",
            )
            for item in batch:
                record = self._api_record_to_ghostmerge(item, field_types)
                record["tags"] = ", ".join(tags_by_id[int(item["id"])])
                records.append(record)
                self.progress(
                    SyncEvent(
                        "fetch",
                        f"Fetched {len(records)} finding(s) from {self.server.name}",
                        len(records),
                        0,
                    )
                )
            if len(batch) < limit:
                break
            offset += limit
        self.progress(SyncEvent("fetch", f"Fetched {len(records)} findings from {self.server.name}", len(records), len(records), "done"))
        return records

    def fetch_template_library(self) -> dict[str, list[dict[str, Any]]]:
        """Fetch both reviewed template libraries from Ghostwriter."""
        return {
            "findings": self.fetch_findings(),
            "observations": self.fetch_observations(),
        }

    def fetch_template_counts(self) -> dict[str, int]:
        """Return current Finding and Observation counts without fetching records."""
        query = """
        query CountTemplates {
          finding_aggregate {
            aggregate { count }
          }
          observation_aggregate {
            aggregate { count }
          }
        }
        """
        self.progress(SyncEvent("count", f"Checking {self.server.name}", 0, 0))
        try:
            data = self.client.execute(query)
            counts = {
                "findings": _parse_template_count(data, "finding_aggregate", "Finding"),
                "observations": _parse_template_count(data, "observation_aggregate", "Observation"),
            }
        except GhostwriterApiError as exc:
            if "Ghostwriter GraphQL error:" not in str(exc):
                raise
            counts = self._fetch_template_counts_by_id()

        total = counts["findings"] + counts["observations"]
        self.progress(
            SyncEvent(
                "count",
                (
                    f"Connected to {self.server.name}; found {counts['findings']} Finding(s) "
                    f"and {counts['observations']} Observation(s)"
                ),
                total,
                total,
                "done",
            )
        )
        return counts

    def _fetch_template_counts_by_id(self) -> dict[str, int]:
        """Count IDs when aggregate queries are unavailable to the configured token."""
        query = """
        query CountTemplateIds($limit: Int!, $findingOffset: Int!, $observationOffset: Int!) {
          finding(limit: $limit, offset: $findingOffset, order_by: {id: asc}) { id }
          observation(limit: $limit, offset: $observationOffset, order_by: {id: asc}) { id }
        }
        """
        limit = 1000
        counts = {"findings": 0, "observations": 0}
        offsets = {"findings": 0, "observations": 0}
        complete = {"findings": False, "observations": False}
        seen_ids: dict[str, set[str]] = {"findings": set(), "observations": set()}

        while not all(complete.values()):
            data = self.client.execute(
                query,
                {
                    "limit": limit,
                    "findingOffset": offsets["findings"],
                    "observationOffset": offsets["observations"],
                },
            )
            for key, response_key, label in (
                ("findings", "finding", "Finding"),
                ("observations", "observation", "Observation"),
            ):
                if complete[key]:
                    continue
                batch = data.get(response_key)
                if not isinstance(batch, list):
                    raise GhostwriterApiError(
                        f"Ghostwriter did not return a {label} list while checking template counts."
                    )
                if not batch:
                    complete[key] = True
                    continue

                page_ids = []
                for item in batch:
                    record_id = item.get("id") if isinstance(item, dict) else None
                    if record_id in (None, ""):
                        raise GhostwriterApiError(
                            f"Ghostwriter returned a {label} without an ID while checking template counts."
                        )
                    page_ids.append(str(record_id))

                if len(set(page_ids)) != len(page_ids) or seen_ids[key].intersection(page_ids):
                    raise GhostwriterApiError(
                        f"Ghostwriter returned repeated {label} IDs while checking template counts; "
                        "pagination did not advance safely."
                    )

                seen_ids[key].update(page_ids)
                offsets[key] += len(batch)
                counts[key] = len(seen_ids[key])

            total = counts["findings"] + counts["observations"]
            self.progress(
                SyncEvent(
                    "count",
                    (
                        f"Counting templates on {self.server.name}: "
                        f"{counts['findings']} Finding(s), {counts['observations']} Observation(s)"
                    ),
                    total,
                    0,
                )
            )

        return counts

    def fetch_observations(self) -> list[dict[str, Any]]:
        field_types = self.fetch_extra_field_specs()["observation"]
        query = """
        query FetchObservations($limit: Int!, $offset: Int!) {
          observation(limit: $limit, offset: $offset, order_by: {id: asc}) {
            id
            title
            description
            extraFields
          }
        }
        """
        records: list[dict[str, Any]] = []
        offset = 0
        limit = 100
        while True:
            self.progress(SyncEvent("fetch", f"Fetching observations from {self.server.name}", len(records), 0))
            data = self.client.execute(query, {"limit": limit, "offset": offset})
            batch = data.get("observation") or []
            if not batch:
                break
            tags_by_id = self.fetch_tags_batch(
                [int(item["id"]) for item in batch],
                model="observation",
            )
            for item in batch:
                record = self._api_observation_to_ghostmerge(item, field_types)
                record["tags"] = ", ".join(tags_by_id[int(item["id"])])
                records.append(record)
                self.progress(
                    SyncEvent(
                        "fetch",
                        f"Fetched {len(records)} observation(s) from {self.server.name}",
                        len(records),
                        0,
                    )
                )
            if len(batch) < limit:
                break
            offset += limit
        self.progress(SyncEvent("fetch", f"Fetched {len(records)} observations from {self.server.name}", len(records), len(records), "done"))
        return records

    def fetch_tags(self, finding_id: int, model: str = "finding") -> list[str]:
        query = """
        query Tags($model: String!, $id: bigint!) {
          tags(model: $model, id: $id) { tags }
        }
        """
        data = self.client.execute(query, {"model": model, "id": finding_id})
        return list((data.get("tags") or {}).get("tags") or [])

    def fetch_tags_batch(self, record_ids: list[int], model: str) -> dict[int, list[str]]:
        """Fetch tags for several records per rate-limited GraphQL request."""
        tags_by_id: dict[int, list[str]] = {}
        for record_id_batch in _batches(record_ids, self.server.sync_batch_size):
            if len(record_id_batch) == 1:
                record_id = record_id_batch[0]
                tags_by_id[record_id] = self.fetch_tags(record_id, model=model)
                continue
            definitions = ["$model: String!"]
            fields = []
            variables: dict[str, Any] = {"model": model}
            for index, record_id in enumerate(record_id_batch):
                definitions.append(f"$id{index}: bigint!")
                fields.append(f"  item{index}: tags(model: $model, id: $id{index}) {{ tags }}")
                variables[f"id{index}"] = record_id
            query = f"query FetchTagsBatch({', '.join(definitions)}) {{\n" + "\n".join(fields) + "\n}"
            data = self.client.execute(query, variables)
            for index, record_id in enumerate(record_id_batch):
                result = data.get(f"item{index}")
                if not isinstance(result, dict):
                    raise GhostwriterApiError(
                        f"Ghostwriter did not return tags for every batched {model} record."
                    )
                tags_by_id[record_id] = list(result.get("tags") or [])
        return tags_by_id

    def create_backup(self, backup_root: Path) -> Path:
        raw_findings = self.fetch_raw_findings_with_tags()
        raw_observations = self.fetch_raw_observations_with_tags()
        field_specs = self.fetch_extra_field_specs()
        normalised_findings = [
            self._api_record_to_ghostmerge(item["record"], field_specs["finding"])
            | {"tags": ", ".join(item["tags"])}
            for item in raw_findings
        ]
        normalised_observations = [
            self._api_observation_to_ghostmerge(item["record"], field_specs["observation"])
            | {"tags": ", ".join(item["tags"])}
            for item in raw_observations
        ]
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup_dir = backup_root / self.server.side
        backup_dir.mkdir(parents=True, exist_ok=True)
        backup_path = backup_dir / f"{timestamp}-{_slug(self.server.name)}-{uuid.uuid4().hex[:8]}.json"
        backup_data = {
            "server_side": self.server.side,
            "server_name": self.server.name,
            "graphql_url": self.server.graphql_url,
            "created_at": timestamp,
            "record_count": len(raw_findings),
            "observation_count": len(raw_observations),
            "findings": {
                "raw_records": raw_findings,
                "normalised_records": normalised_findings,
            },
            "observations": {
                "raw_records": raw_observations,
                "normalised_records": normalised_observations,
            },
            # Preserve top-level finding keys so older tools and tests can still read the backup.
            "raw_records": raw_findings,
            "normalised_records": normalised_findings,
        }
        with backup_path.open("x", encoding="utf-8") as handle:
            json.dump(backup_data, handle, indent=2)
        verify_backup(backup_path)
        total_records = len(raw_findings) + len(raw_observations)
        self.progress(
            SyncEvent(
                "backup",
                f"Backup written for {self.server.name}",
                total_records,
                total_records,
                "done",
                backup_path=str(backup_path),
            )
        )
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
            self.progress(SyncEvent("backup_fetch", f"Fetching backup records from {self.server.name}", len(raw_records), 0))
            data = self.client.execute(query, {"limit": limit, "offset": offset})
            batch = data.get("finding") or []
            if not batch:
                break
            tags_by_id = self.fetch_tags_batch(
                [int(item["id"]) for item in batch],
                model="finding",
            )
            for item in batch:
                raw_records.append({"record": item, "tags": tags_by_id[int(item["id"])]})
                self.progress(
                    SyncEvent(
                        "backup_fetch",
                        f"Fetched {len(raw_records)} backup record(s) from {self.server.name}",
                        len(raw_records),
                        0,
                    )
                )
            if len(batch) < limit:
                break
            offset += limit
        self.progress(
            SyncEvent(
                "backup_fetch",
                f"Fetched {len(raw_records)} backup record(s) from {self.server.name}",
                len(raw_records),
                len(raw_records),
                "done",
            )
        )
        return raw_records

    def fetch_raw_observations_with_tags(self) -> list[dict[str, Any]]:
        query = """
        query FetchRawObservations($limit: Int!, $offset: Int!) {
          observation(limit: $limit, offset: $offset, order_by: {id: asc}) {
            id
            title
            description
            extraFields
          }
        }
        """
        raw_records: list[dict[str, Any]] = []
        offset = 0
        limit = 100
        while True:
            self.progress(SyncEvent("backup_fetch", f"Fetching observation backup records from {self.server.name}", len(raw_records), 0))
            data = self.client.execute(query, {"limit": limit, "offset": offset})
            batch = data.get("observation") or []
            if not batch:
                break
            tags_by_id = self.fetch_tags_batch(
                [int(item["id"]) for item in batch],
                model="observation",
            )
            for item in batch:
                raw_records.append({"record": item, "tags": tags_by_id[int(item["id"])]})
                self.progress(
                    SyncEvent(
                        "backup_fetch",
                        f"Fetched {len(raw_records)} observation backup record(s) from {self.server.name}",
                        len(raw_records),
                        0,
                    )
                )
            if len(batch) < limit:
                break
            offset += limit
        self.progress(
            SyncEvent(
                "backup_fetch",
                f"Fetched {len(raw_records)} observation backup record(s) from {self.server.name}",
                len(raw_records),
                len(raw_records),
                "done",
            )
        )
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
                "Use a Ghostwriter API token or service token with read/write access to Finding Templates, "
                "Observation Templates, and tags."
            )

    def replace_all_findings(
        self,
        records: list[dict[str, Any]],
        backup_root: Path,
        observations: Optional[list[dict[str, Any]]] = None,
    ) -> Path:
        replace_observations = observations is not None
        self.preflight_sync_permissions()
        lookups = self.fetch_lookup_ids()
        sync_timestamp = _utc_timestamp()
        prepared_records = self.prepare_records_for_reload(records, lookups, last_synced_at=sync_timestamp)
        prepared_observations = (
            self.prepare_observations_for_reload(observations, last_synced_at=sync_timestamp)
            if replace_observations
            else []
        )
        backup_path = self.create_backup(backup_root)
        self.validate_prepared_records_can_be_created(prepared_records, prepared_observations)
        existing_ids = self.fetch_finding_ids()
        existing_observation_ids = self.fetch_observation_ids() if replace_observations else []
        deleted = 0
        delete_total = len(existing_ids) + len(existing_observation_ids)
        for finding_ids in _batches(existing_ids, self.server.sync_batch_size):
            self.delete_findings(finding_ids)
            deleted += len(finding_ids)
            self.progress(
                SyncEvent(
                    "delete",
                    f"Deleting existing findings from {self.server.name}",
                    deleted,
                    delete_total,
                )
            )
        if replace_observations:
            for observation_ids in _batches(existing_observation_ids, self.server.sync_batch_size):
                self.delete_observations(observation_ids)
                deleted += len(observation_ids)
                self.progress(
                    SyncEvent(
                        "delete",
                        f"Deleting existing observations from {self.server.name}",
                        deleted,
                        delete_total,
                    )
                )
        created = 0
        create_total = len(prepared_records) + len(prepared_observations)
        for prepared_batch in _batches(prepared_records, self.server.sync_batch_size):
            created_ids = self.create_prepared_findings(
                [prepared["api_record"] for prepared in prepared_batch]
            )
            self.set_tags_batch(
                [
                    (created_id, prepared["tags"])
                    for created_id, prepared in zip(created_ids, prepared_batch, strict=True)
                ],
                model="finding",
            )
            created += len(prepared_batch)
            self.progress(
                SyncEvent(
                    "create",
                    f"Creating reviewed findings on {self.server.name}",
                    created,
                    create_total,
                )
            )
        if replace_observations:
            for prepared_batch in _batches(prepared_observations, self.server.sync_batch_size):
                created_ids = self.create_prepared_observations(
                    [prepared["api_record"] for prepared in prepared_batch]
                )
                self.set_tags_batch(
                    [
                        (created_id, prepared["tags"])
                        for created_id, prepared in zip(created_ids, prepared_batch, strict=True)
                    ],
                    model="observation",
                )
                created += len(prepared_batch)
                self.progress(
                    SyncEvent(
                        "create",
                        f"Creating reviewed observations on {self.server.name}",
                        created,
                        create_total,
                    )
                )
        total_records = len(records) + len(prepared_observations)
        self.progress(SyncEvent("complete", f"Sync complete for {self.server.name}", total_records, total_records, "done"))
        return backup_path

    def validate_prepared_records_can_be_created(
        self,
        prepared_records: list[dict[str, Any]],
        prepared_observations: Optional[list[dict[str, Any]]] = None,
    ) -> None:
        """Apply the configured temporary-creation check before live deletion.

        Preflight schema checks prove that required mutations exist, but they do
        not prove that a prepared payload is acceptable to Ghostwriter. Full or
        sampled validation catches create/tag failures while the existing
        library is still intact, then removes every temporary record.
        """
        created_findings: list[int] = []
        created_observations: list[int] = []
        prepared_observations = prepared_observations or []
        validation_findings = self._validation_records(prepared_records)
        validation_observations = self._validation_records(prepared_observations)
        total = len(validation_findings) + len(validation_observations)

        if not total:
            self.progress(
                SyncEvent(
                    "validate_skipped",
                    f"Temporary creation validation skipped for {self.server.name}",
                    0,
                    0,
                    "done",
                )
            )
            return

        try:
            complete = 0
            for prepared_batch in _batches(validation_findings, self.server.sync_batch_size):
                created_ids = self.create_prepared_findings(
                    [prepared["api_record"] for prepared in prepared_batch]
                )
                created_findings.extend(created_ids)
                self.set_tags_batch(
                    [
                        (created_id, prepared["tags"])
                        for created_id, prepared in zip(created_ids, prepared_batch, strict=True)
                    ],
                    model="finding",
                )
                # Report completed work only after both creation and tagging
                # have succeeded.  This avoids showing 100% while the final
                # validation request is still in flight.
                complete += len(prepared_batch)
                self.progress(
                    SyncEvent(
                        "validate_create",
                        f"Validated reviewed findings on {self.server.name}",
                        complete,
                        total,
                    )
                )

            for prepared_batch in _batches(validation_observations, self.server.sync_batch_size):
                created_ids = self.create_prepared_observations(
                    [prepared["api_record"] for prepared in prepared_batch]
                )
                created_observations.extend(created_ids)
                self.set_tags_batch(
                    [
                        (created_id, prepared["tags"])
                        for created_id, prepared in zip(created_ids, prepared_batch, strict=True)
                    ],
                    model="observation",
                )
                complete += len(prepared_batch)
                self.progress(
                    SyncEvent(
                        "validate_create",
                        f"Validated reviewed observations on {self.server.name}",
                        complete,
                        total,
                    )
                )
        finally:
            cleanup_errors = []
            cleanup_total = len(created_findings) + len(created_observations)
            cleanup_complete = 0
            if cleanup_total:
                try:
                    self.progress(
                        SyncEvent(
                            "validate_cleanup",
                            f"Removing temporary validation records from {self.server.name}",
                            0,
                            cleanup_total,
                        )
                    )
                except Exception as exc:
                    # Continue with every deletion even when the status store
                    # cannot persist the transition into the cleanup stage.
                    cleanup_errors.append(f"progress before validation cleanup: {exc}")
            for finding_ids in _batches(list(reversed(created_findings)), self.server.sync_batch_size):
                deletion_errors = self._cleanup_validation_records(finding_ids, model="finding")
                cleanup_errors.extend(deletion_errors)
                if not deletion_errors:
                    cleanup_complete += len(finding_ids)
                    try:
                        self.progress(
                            SyncEvent(
                                "validate_cleanup",
                                f"Removing temporary validation findings from {self.server.name}",
                                cleanup_complete,
                                cleanup_total,
                            )
                        )
                    except Exception as exc:
                        # A status persistence error must not stop the remaining
                        # temporary records from being removed.
                        cleanup_errors.append(f"progress after findings {finding_ids}: {exc}")
            for observation_ids in _batches(list(reversed(created_observations)), self.server.sync_batch_size):
                deletion_errors = self._cleanup_validation_records(observation_ids, model="observation")
                cleanup_errors.extend(deletion_errors)
                if not deletion_errors:
                    cleanup_complete += len(observation_ids)
                    try:
                        self.progress(
                            SyncEvent(
                                "validate_cleanup",
                                f"Removing temporary validation observations from {self.server.name}",
                                cleanup_complete,
                                cleanup_total,
                            )
                        )
                    except Exception as exc:
                        cleanup_errors.append(f"progress after observations {observation_ids}: {exc}")
            if cleanup_errors:
                raise GhostwriterApiError(
                    "Creation validation cleanup failed; existing library was not replaced. "
                    + "; ".join(cleanup_errors)
                )

        # This event makes the transition out of temporary validation explicit;
        # the Web worker keeps the overall sync running until the later, final
        # replacement completion event.
        self.progress(
            SyncEvent(
                "validate_complete",
                f"Validation complete for {self.server.name}",
                total,
                total,
                "done",
            )
        )

    def _cleanup_validation_records(self, record_ids: list[int], *, model: str) -> list[str]:
        """Retry every temporary record separately if its batched deletion fails."""
        delete_batch = self.delete_findings if model == "finding" else self.delete_observations
        delete_one = self.delete_finding if model == "finding" else self.delete_observation
        try:
            delete_batch(record_ids)
            return []
        except Exception as batch_error:
            individual_errors = []
            for record_id in record_ids:
                try:
                    delete_one(record_id)
                except Exception as exc:
                    individual_errors.append(f"{model} {record_id}: {exc}")
            if individual_errors:
                return [
                    f"{model} batch {record_ids} failed ({batch_error}); "
                    + "; ".join(individual_errors)
                ]
            return []

    def _validation_records(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if self.server.sync_validation_mode == "none":
            return []
        if self.server.sync_validation_mode == "sample":
            return records[: self.server.sync_validation_sample_size]
        return records

    def prepare_records_for_reload(
        self,
        records: list[dict[str, Any]],
        lookups: dict[str, dict[str, int]],
        last_synced_at: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        prepared_records = []
        for index, record in enumerate(records, start=1):
            try:
                api_record = ghostmerge_record_to_api_input(record, lookups, last_synced_at=last_synced_at)
                tags = _split_tags(record.get("tags"))
            except Exception as exc:
                title = record.get("title") or f"record {index}"
                raise GhostwriterApiError(f"Cannot prepare Finding Template {index} ({title}) for reload: {exc}") from exc
            prepared_records.append({"api_record": api_record, "tags": tags})
        return prepared_records

    def prepare_observations_for_reload(
        self,
        records: list[dict[str, Any]],
        last_synced_at: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        prepared_records = []
        for index, record in enumerate(records, start=1):
            try:
                api_record = ghostmerge_observation_to_api_input(record, last_synced_at=last_synced_at)
                tags = _split_tags(record.get("tags"))
            except Exception as exc:
                title = record.get("title") or f"record {index}"
                raise GhostwriterApiError(f"Cannot prepare Observation Template {index} ({title}) for reload: {exc}") from exc
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

    def fetch_observation_ids(self) -> list[int]:
        query = """
        query ObservationIds {
          observation(order_by: {id: asc}) { id }
        }
        """
        data = self.client.execute(query)
        return [int(item["id"]) for item in data.get("observation", [])]

    def delete_finding(self, finding_id: int) -> None:
        mutation = """
        mutation DeleteFinding($id: bigint!) {
          delete_finding_by_pk(id: $id) { id }
        }
        """
        self.client.execute(mutation, {"id": finding_id})

    def delete_findings(self, finding_ids: list[int]) -> None:
        """Delete one request-sized batch of Finding Templates."""
        if len(finding_ids) == 1:
            self.delete_finding(finding_ids[0])
            return
        query, variables = _aliased_mutation(
            "DeleteFindings",
            "delete_finding_by_pk",
            finding_ids,
            variable_type="bigint!",
            argument_name="id",
            selection="{ id }",
        )
        self.client.execute(query, variables)

    def delete_observation(self, observation_id: int) -> None:
        mutation = """
        mutation DeleteObservation($id: bigint!) {
          delete_observation_by_pk(id: $id) { id }
        }
        """
        self.client.execute(mutation, {"id": observation_id})

    def delete_observations(self, observation_ids: list[int]) -> None:
        """Delete one request-sized batch of Observation Templates."""
        if len(observation_ids) == 1:
            self.delete_observation(observation_ids[0])
            return
        query, variables = _aliased_mutation(
            "DeleteObservations",
            "delete_observation_by_pk",
            observation_ids,
            variable_type="bigint!",
            argument_name="id",
            selection="{ id }",
        )
        self.client.execute(query, variables)

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

    def create_prepared_findings(self, api_records: list[dict[str, Any]]) -> list[int]:
        """Create one request-sized batch and preserve input-to-ID ordering."""
        if len(api_records) == 1:
            return [self.create_prepared_finding(api_records[0])]
        query, variables = _aliased_mutation(
            "CreateFindings",
            "insert_finding_one",
            api_records,
            variable_type="finding_insert_input!",
            argument_name="object",
            selection="{ id }",
        )
        data = self.client.execute(query, variables)
        return _created_ids(data, len(api_records), "finding")

    def create_prepared_observation(self, api_record: dict[str, Any]) -> int:
        mutation = """
        mutation CreateObservation($object: observation_insert_input!) {
          insert_observation_one(object: $object) { id }
        }
        """
        data = self.client.execute(mutation, {"object": api_record})
        created = data.get("insert_observation_one")
        if not created:
            raise GhostwriterApiError("Ghostwriter did not return the created observation ID.")
        return int(created["id"])

    def create_prepared_observations(self, api_records: list[dict[str, Any]]) -> list[int]:
        """Create one request-sized Observation batch and return ordered IDs."""
        if len(api_records) == 1:
            return [self.create_prepared_observation(api_records[0])]
        query, variables = _aliased_mutation(
            "CreateObservations",
            "insert_observation_one",
            api_records,
            variable_type="observation_insert_input!",
            argument_name="object",
            selection="{ id }",
        )
        data = self.client.execute(query, variables)
        return _created_ids(data, len(api_records), "observation")

    def set_tags(self, finding_id: int, tags: list[str], model: str = "finding") -> None:
        mutation = """
        mutation SetFindingTags($model: String!, $id: bigint!, $tags: [String!]!) {
          setTags(model: $model, id: $id, tags: $tags) { tags }
        }
        """
        self.client.execute(mutation, {"model": model, "id": finding_id, "tags": tags})

    def set_tags_batch(self, records: list[tuple[int, list[str]]], model: str) -> None:
        """Apply tags to several records in one GraphQL request."""
        if len(records) == 1:
            record_id, tags = records[0]
            self.set_tags(record_id, tags, model=model)
            return
        definitions = ["$model: String!"]
        fields = []
        variables: dict[str, Any] = {"model": model}
        for index, (record_id, tags) in enumerate(records):
            definitions.extend((f"$id{index}: bigint!", f"$tags{index}: [String!]!"))
            fields.append(
                f"  item{index}: setTags(model: $model, id: $id{index}, tags: $tags{index}) {{ tags }}"
            )
            variables[f"id{index}"] = record_id
            variables[f"tags{index}"] = tags
        query = f"mutation SetTagsBatch({', '.join(definitions)}) {{\n" + "\n".join(fields) + "\n}"
        self.client.execute(query, variables)

    def restore_backup_record(self, backup_record: dict[str, Any], replace_existing_id: Optional[int] = None) -> int:
        if replace_existing_id is not None:
            self.delete_finding(int(replace_existing_id))
        lookups = self.fetch_lookup_ids()
        record = backup_record.get("normalised_record") or backup_record
        created_id = self.create_finding(record, lookups)
        self.set_tags(created_id, _split_tags(record.get("tags")))
        return created_id

    def restore_observation_backup_record(self, backup_record: dict[str, Any], replace_existing_id: Optional[int] = None) -> int:
        if replace_existing_id is not None:
            self.delete_observation(int(replace_existing_id))
        record = backup_record.get("normalised_record") or backup_record
        created_id = self.create_prepared_observation(ghostmerge_observation_to_api_input(record))
        self.set_tags(created_id, _split_tags(record.get("tags")), model="observation")
        return created_id

    def find_restore_candidates(self, backup_record: dict[str, Any]) -> list[dict[str, Any]]:
        record = backup_record.get("normalised_record") or backup_record
        raw_record = (backup_record.get("raw_record") or {}).get("record") or {}
        original_id = _optional_int(raw_record.get("id") or record.get("id"))
        title = str(record.get("title") or "").strip()
        finding_type = str(record.get("finding_type") or "").strip()
        candidates = []
        seen_ids = set()
        for existing in self.fetch_findings():
            existing_id = _optional_int(existing.get("id"))
            if existing_id is None or existing_id in seen_ids:
                continue
            id_matches = original_id is not None and existing_id == original_id
            title_type_matches = (
                title
                and finding_type
                and str(existing.get("title") or "").strip() == title
                and str(existing.get("finding_type") or "").strip() == finding_type
            )
            if id_matches or title_type_matches:
                reasons = []
                if id_matches:
                    reasons.append("same original Ghostwriter ID")
                if title_type_matches:
                    reasons.append("same title and finding type")
                candidates.append(
                    {
                        "id": existing_id,
                        "title": existing.get("title") or "",
                        "finding_type": existing.get("finding_type") or "",
                        "severity": existing.get("severity") or "",
                        "match_reason": ", ".join(reasons),
                    }
                )
                seen_ids.add(existing_id)
        return candidates

    def find_observation_restore_candidates(self, backup_record: dict[str, Any]) -> list[dict[str, Any]]:
        record = backup_record.get("normalised_record") or backup_record
        raw_record = (backup_record.get("raw_record") or {}).get("record") or {}
        original_id = _optional_int(raw_record.get("id") or record.get("id"))
        title = str(record.get("title") or "").strip()
        candidates = []
        seen_ids = set()
        for existing in self.fetch_observations():
            existing_id = _optional_int(existing.get("id"))
            if existing_id is None or existing_id in seen_ids:
                continue
            id_matches = original_id is not None and existing_id == original_id
            title_matches = title and str(existing.get("title") or "").strip() == title
            if id_matches or title_matches:
                reasons = []
                if id_matches:
                    reasons.append("same original Ghostwriter ID")
                if title_matches:
                    reasons.append("same title")
                candidates.append(
                    {
                        "id": existing_id,
                        "title": existing.get("title") or "",
                        "finding_type": "",
                        "severity": "",
                        "match_reason": ", ".join(reasons),
                    }
                )
                seen_ids.add(existing_id)
        return candidates

    def _api_record_to_ghostmerge(
        self,
        record: dict[str, Any],
        field_types: Optional[dict[str, str]] = None,
    ) -> dict[str, Any]:
        extra_fields = apply_configured_extra_fields_normalisation(
            record.get("extraFields") or {},
            field_types,
        )
        extra_fields = apply_extra_fields_key_migrations(
            extra_fields,
            template_type="finding",
        )
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
            "extra_fields": extra_fields,
        }

    def _api_observation_to_ghostmerge(
        self,
        record: dict[str, Any],
        field_types: Optional[dict[str, str]] = None,
    ) -> dict[str, Any]:
        extra_fields = apply_configured_extra_fields_normalisation(
            record.get("extraFields") or {},
            field_types,
        )
        extra_fields = apply_extra_fields_key_migrations(
            extra_fields,
            template_type="observation",
        )
        return {
            "id": str(record.get("id", "")),
            "title": record.get("title") or "",
            "description": record.get("description") or "",
            "tags": "",
            "extra_fields": extra_fields,
        }


def ghostmerge_record_to_api_input(
    record: dict[str, Any],
    lookups: dict[str, dict[str, int]],
    last_synced_at: Optional[str] = None,
) -> dict[str, Any]:
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
        "extraFields": _extra_fields(record.get("extra_fields"), last_synced_at=last_synced_at),
    }


def ghostmerge_observation_to_api_input(
    record: dict[str, Any],
    last_synced_at: Optional[str] = None,
) -> dict[str, Any]:
    return {
        "title": record.get("title") or "",
        "description": record.get("description") or "",
        "extraFields": _extra_fields(record.get("extra_fields"), last_synced_at=last_synced_at),
    }


def _batches(items: list[Any], batch_size: int) -> list[list[Any]]:
    """Split a materialised collection into non-empty request-sized batches."""
    return [items[start : start + batch_size] for start in range(0, len(items), batch_size)]


def _aliased_mutation(
    operation_name: str,
    field_name: str,
    values: list[Any],
    *,
    variable_type: str,
    argument_name: str,
    selection: str,
) -> tuple[str, dict[str, Any]]:
    """Build a bounded GraphQL mutation using stable aliases and variables."""
    definitions = [f"$value{index}: {variable_type}" for index in range(len(values))]
    fields = [
        f"  item{index}: {field_name}({argument_name}: $value{index}) {selection}"
        for index in range(len(values))
    ]
    query = f"mutation {operation_name}({', '.join(definitions)}) {{\n" + "\n".join(fields) + "\n}"
    return query, {f"value{index}": value for index, value in enumerate(values)}


def _created_ids(data: dict[str, Any], expected_count: int, template_type: str) -> list[int]:
    created_ids = []
    for index in range(expected_count):
        created = data.get(f"item{index}")
        if not isinstance(created, dict) or created.get("id") is None:
            raise GhostwriterApiError(
                f"Ghostwriter did not return every created {template_type} ID for a batched request."
            )
        created_ids.append(int(created["id"]))
    return created_ids


def load_server_configs(config: dict[str, Any]) -> dict[str, Optional[GhostwriterServerConfig]]:
    api_config = config.get("ghostwriter_api", {})
    servers = api_config.get("servers", {})
    default_rate = float(api_config.get("default_rate_limit_per_second", 0.2))
    default_batch_size = _sync_batch_size(api_config.get("sync_batch_size", 25))
    default_validation_mode = _validation_mode(api_config.get("sync_validation_mode", "full"))
    default_sample_size = _positive_config_int(
        api_config.get("sync_validation_sample_size", 10),
        "sync_validation_sample_size",
    )
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
            sync_batch_size=_sync_batch_size(
                server.get("sync_batch_size", default_batch_size),
                side=side,
            ),
            sync_validation_mode=_validation_mode(
                server.get("sync_validation_mode", default_validation_mode),
                side=side,
            ),
            sync_validation_sample_size=_positive_config_int(
                server.get("sync_validation_sample_size", default_sample_size),
                f"{side} sync_validation_sample_size",
            ),
        )
    return parsed


def _positive_config_int(value: Any, setting_name: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise GhostwriterApiError(f"Ghostwriter API {setting_name} must be a positive integer.") from exc
    if parsed < 1:
        raise GhostwriterApiError(f"Ghostwriter API {setting_name} must be a positive integer.")
    return parsed


def _sync_batch_size(value: Any, *, side: Optional[str] = None) -> int:
    prefix = f"{side} " if side else ""
    parsed = _positive_config_int(value, f"{prefix}sync_batch_size")
    if parsed > MAX_SYNC_BATCH_SIZE:
        raise GhostwriterApiError(
            f"Ghostwriter API {prefix}sync_batch_size must not exceed {MAX_SYNC_BATCH_SIZE}."
        )
    return parsed


def _validation_mode(value: Any, *, side: Optional[str] = None) -> str:
    parsed = str(value or "").strip().lower()
    if parsed not in SYNC_VALIDATION_MODES:
        prefix = f"{side} " if side else ""
        allowed = ", ".join(sorted(SYNC_VALIDATION_MODES))
        raise GhostwriterApiError(
            f"Ghostwriter API {prefix}sync_validation_mode must be one of: {allowed}."
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
            "sync_batch_size": server.sync_batch_size if server else None,
            "sync_validation_mode": server.sync_validation_mode if server else None,
            "sync_validation_sample_size": server.sync_validation_sample_size if server else None,
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
    findings = data.get("findings") or {
        "raw_records": data.get("raw_records"),
        "normalised_records": data.get("normalised_records"),
    }
    observations = data.get("observations") or {"raw_records": [], "normalised_records": []}

    if not isinstance(findings.get("raw_records"), list):
        raise GhostwriterApiError("Backup does not contain finding raw_records.")
    if not isinstance(findings.get("normalised_records"), list):
        raise GhostwriterApiError("Backup does not contain finding normalised_records.")
    if not isinstance(observations.get("raw_records"), list):
        raise GhostwriterApiError("Backup does not contain observation raw_records.")
    if not isinstance(observations.get("normalised_records"), list):
        raise GhostwriterApiError("Backup does not contain observation normalised_records.")

    data["findings"] = findings
    data["observations"] = observations
    data["raw_records"] = findings["raw_records"]
    data["normalised_records"] = findings["normalised_records"]
    data.setdefault("record_count", len(findings["raw_records"]))
    data.setdefault("observation_count", len(observations["raw_records"]))

    if data.get("record_count") != len(findings["raw_records"]):
        raise GhostwriterApiError("Backup record count does not match its contents.")
    if len(findings["normalised_records"]) != len(findings["raw_records"]):
        raise GhostwriterApiError("Backup raw and normalised record counts do not match.")
    if data.get("observation_count") != len(observations["raw_records"]):
        raise GhostwriterApiError("Backup observation count does not match its contents.")
    if len(observations["normalised_records"]) != len(observations["raw_records"]):
        raise GhostwriterApiError("Backup observation raw and normalised record counts do not match.")
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
                "observation_count": data.get("observation_count", 0),
            }
        )
    return backups


def load_backup_record(path: Path, index: int, template_type: str = "finding") -> dict[str, Any]:
    data = verify_backup(path)
    if template_type not in {"finding", "observation"}:
        raise GhostwriterApiError("Unknown backup template type.")
    section = data["findings"] if template_type == "finding" else data["observations"]
    records = section["normalised_records"]
    if index < 0 or index >= len(records):
        raise GhostwriterApiError("Backup record index is out of range.")
    return {
        "backup": data,
        "normalised_record": records[index],
        "raw_record": section["raw_records"][index],
        "index": index,
        "template_type": template_type,
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


def _optional_int(value: Any) -> Optional[int]:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _parse_template_count(data: Any, aggregate_key: str, label: str) -> int:
    """Extract a non-negative aggregate count from a Ghostwriter response."""
    if not isinstance(data, dict):
        raise GhostwriterApiError(f"Ghostwriter did not return {label} count data.")
    aggregate = data.get(aggregate_key)
    aggregate_fields = aggregate.get("aggregate") if isinstance(aggregate, dict) else None
    value = aggregate_fields.get("count") if isinstance(aggregate_fields, dict) else None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise GhostwriterApiError(f"Ghostwriter did not return a valid {label} count.")
    return value


def _extra_fields(value: Any, last_synced_at: Optional[str] = None) -> dict[str, Any]:
    if value in (None, ""):
        fields = {}
    elif isinstance(value, dict):
        fields = dict(value)
    elif isinstance(value, str):
        parsed = json.loads(value)
        if not isinstance(parsed, dict):
            raise GhostwriterApiError("extra_fields must be a JSON object.")
        fields = parsed
    else:
        raise GhostwriterApiError("extra_fields must be a JSON object.")
    if last_synced_at:
        fields[GHOSTMERGE_LAST_SYNCED_AT_FIELD] = last_synced_at
    return fields


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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
