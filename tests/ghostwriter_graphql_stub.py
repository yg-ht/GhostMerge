"""Stateful localhost GraphQL test server for Ghostwriter integration tests.

The production client deliberately uses only the Python standard library.  This
stub does the same so integration tests exercise the real HTTP request path
without introducing another dependency or contacting an external service.
"""

from __future__ import annotations

import copy
import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


def ghostwriter_finding_record(record_id: int, title: str, *, extra_fields: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build the stored GraphQL shape for a conventional Web finding."""
    return {
        "id": record_id,
        "severity": {"id": 3, "severity": "Medium"},
        "type": {"id": 7, "findingType": "Web"},
        "cvssScore": 5.0,
        "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "title": title,
        "description": f"Existing content for {title}",
        "impact": "",
        "mitigation": "",
        "replication_steps": "",
        "hostDetectionTechniques": "",
        "networkDetectionTechniques": "",
        "references": "",
        "findingGuidance": "",
        "extraFields": copy.deepcopy(extra_fields or {}),
    }


def ghostwriter_observation_record(
    record_id: int,
    title: str,
    *,
    extra_fields: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the stored GraphQL shape for an Observation Template."""
    return {
        "id": record_id,
        "title": title,
        "description": f"Existing content for {title}",
        "extraFields": copy.deepcopy(extra_fields or {}),
    }


class GhostwriterGraphQLStub:
    """Maintain a small Ghostwriter-like template library behind HTTP GraphQL."""

    def __init__(
        self,
        *,
        bearer_token: str,
        findings: list[dict[str, Any]] | None = None,
        observations: list[dict[str, Any]] | None = None,
        tags: dict[tuple[str, int], list[str]] | None = None,
        fail_on_operation_call: dict[str, int] | None = None,
    ) -> None:
        self.bearer_token = bearer_token
        self.findings = copy.deepcopy(findings or [])
        self.observations = copy.deepcopy(observations or [])
        self.tags = copy.deepcopy(tags or {})
        self.requests: list[dict[str, Any]] = []
        self.fail_on_operation_call = dict(fail_on_operation_call or {})
        self.operation_calls: dict[str, int] = {}
        self._next_finding_id = max((int(item["id"]) for item in self.findings), default=0) + 1
        self._next_observation_id = max((int(item["id"]) for item in self.observations), default=0) + 1
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def graphql_url(self) -> str:
        """Return the ephemeral URL after the stub has started."""
        if self._server is None:
            raise RuntimeError("Ghostwriter GraphQL stub has not been started.")
        host, port = self._server.server_address
        return f"http://{host}:{port}/v1/graphql"

    def start(self) -> None:
        """Start the server on a loopback-only ephemeral port."""
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
                if self.path != "/v1/graphql":
                    self.send_error(404)
                    return
                if self.headers.get("Authorization") != f"Bearer {stub.bearer_token}":
                    self._write_json(401, {"errors": [{"message": "Unauthorised"}]})
                    return
                try:
                    content_length = int(self.headers.get("Content-Length", "0"))
                    payload = json.loads(self.rfile.read(content_length).decode("utf-8"))
                    query = str(payload.get("query") or "")
                    variables = payload.get("variables") or {}
                    stub.requests.append({"query": query, "variables": copy.deepcopy(variables)})
                    data = stub.execute(query, variables)
                except Exception as exc:  # pragma: no cover - converted into a client-visible failure
                    self._write_json(200, {"errors": [{"message": str(exc)}]})
                    return
                self._write_json(200, {"data": data})

            def _write_json(self, status: int, payload: dict[str, Any]) -> None:
                body = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: Any) -> None:
                # Test output should contain assertions and failures, not HTTP access noise.
                return

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        """Stop the server and release its loopback port."""
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._server = None
        self._thread = None

    def execute(self, query: str, variables: dict[str, Any]) -> dict[str, Any]:
        """Handle the GraphQL operations used by GhostMerge sync."""
        if "SyncPreflight" in query:
            return {
                "__schema": {
                    "queryType": {
                        "fields": [
                            {"name": name}
                            for name in ("finding", "findingSeverity", "findingType", "observation", "tags")
                        ]
                    },
                    "mutationType": {
                        "fields": [
                            {"name": name}
                            for name in (
                                "delete_finding_by_pk",
                                "insert_finding_one",
                                "delete_observation_by_pk",
                                "insert_observation_one",
                                "setTags",
                            )
                        ]
                    },
                }
            }
        if "FindingLookups" in query:
            return {
                "findingSeverity": [
                    {"id": 1, "severity": "Informational"},
                    {"id": 2, "severity": "Low"},
                    {"id": 3, "severity": "Medium"},
                    {"id": 4, "severity": "High"},
                    {"id": 5, "severity": "Critical"},
                ],
                "findingType": [{"id": 7, "findingType": "Web"}],
            }
        if "FetchRawFindings" in query or "FetchFindings" in query:
            return {"finding": self._page(self.findings, variables)}
        if "FetchRawObservations" in query or "FetchObservations" in query:
            return {"observation": self._page(self.observations, variables)}
        if "FindingIds" in query:
            return {"finding": [{"id": item["id"]} for item in self.findings]}
        if "ObservationIds" in query:
            return {"observation": [{"id": item["id"]} for item in self.observations]}
        if "DeleteFinding" in query:
            self._raise_configured_failure("DeleteFinding")
            record_id = int(variables["id"])
            self.findings = [item for item in self.findings if int(item["id"]) != record_id]
            self.tags.pop(("finding", record_id), None)
            return {"delete_finding_by_pk": {"id": record_id}}
        if "DeleteObservation" in query:
            self._raise_configured_failure("DeleteObservation")
            record_id = int(variables["id"])
            self.observations = [item for item in self.observations if int(item["id"]) != record_id]
            self.tags.pop(("observation", record_id), None)
            return {"delete_observation_by_pk": {"id": record_id}}
        if "CreateFinding" in query:
            self._raise_configured_failure("CreateFinding")
            record_id = self._next_finding_id
            self._next_finding_id += 1
            self.findings.append(self._finding_from_input(record_id, variables["object"]))
            return {"insert_finding_one": {"id": record_id}}
        if "CreateObservation" in query:
            self._raise_configured_failure("CreateObservation")
            record_id = self._next_observation_id
            self._next_observation_id += 1
            self.observations.append(self._observation_from_input(record_id, variables["object"]))
            return {"insert_observation_one": {"id": record_id}}
        if "SetFindingTags" in query:
            self._raise_configured_failure("SetTags")
            model = str(variables["model"])
            record_id = int(variables["id"])
            record_tags = list(variables.get("tags") or [])
            self.tags[(model, record_id)] = record_tags
            return {"setTags": {"tags": record_tags}}
        if "Tags(" in query:
            model = str(variables["model"])
            record_id = int(variables["id"])
            return {"tags": {"tags": copy.deepcopy(self.tags.get((model, record_id), []))}}
        raise AssertionError(f"Unsupported GraphQL operation: {query}")

    def _raise_configured_failure(self, operation: str) -> None:
        """Raise on an exact operation occurrence to exercise partial-failure handling."""
        call_number = self.operation_calls.get(operation, 0) + 1
        self.operation_calls[operation] = call_number
        if self.fail_on_operation_call.get(operation) == call_number:
            raise RuntimeError(f"Configured {operation} failure on call {call_number}.")

    @staticmethod
    def _page(records: list[dict[str, Any]], variables: dict[str, Any]) -> list[dict[str, Any]]:
        offset = int(variables.get("offset", 0))
        limit = int(variables.get("limit", len(records) or 100))
        return copy.deepcopy(records[offset : offset + limit])

    @staticmethod
    def _finding_from_input(record_id: int, value: dict[str, Any]) -> dict[str, Any]:
        severity_names = {1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}
        finding_type_names = {7: "Web"}
        severity_id = int(value["severityId"])
        finding_type_id = int(value["findingTypeId"])
        return {
            "id": record_id,
            "title": value.get("title") or "",
            "cvssScore": value.get("cvssScore"),
            "cvssVector": value.get("cvssVector") or "",
            "description": value.get("description") or "",
            "impact": value.get("impact") or "",
            "mitigation": value.get("mitigation") or "",
            "replication_steps": value.get("replication_steps") or "",
            "hostDetectionTechniques": value.get("hostDetectionTechniques") or "",
            "networkDetectionTechniques": value.get("networkDetectionTechniques") or "",
            "references": value.get("references") or "",
            "findingGuidance": value.get("findingGuidance") or "",
            "extraFields": copy.deepcopy(value.get("extraFields") or {}),
            "severity": {"id": severity_id, "severity": severity_names[severity_id]},
            "type": {"id": finding_type_id, "findingType": finding_type_names[finding_type_id]},
        }

    @staticmethod
    def _observation_from_input(record_id: int, value: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": record_id,
            "title": value.get("title") or "",
            "description": value.get("description") or "",
            "extraFields": copy.deepcopy(value.get("extraFields") or {}),
        }


@contextmanager
def running_ghostwriter_stub(**kwargs: Any) -> Iterator[GhostwriterGraphQLStub]:
    """Run a stub for the duration of one integration-test context."""
    stub = GhostwriterGraphQLStub(**kwargs)
    stub.start()
    try:
        yield stub
    finally:
        stub.close()
