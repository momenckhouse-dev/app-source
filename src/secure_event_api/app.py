"""secure-event-api: ingests security events and archives them to S3."""

from __future__ import annotations

import json
import logging
import os
import random
import re
import time
import uuid
from datetime import UTC, datetime

from flask import Flask, Response, g, jsonify, request
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

VALID_SEVERITIES = ("low", "medium", "high", "critical")
REQUIRED_FIELDS = ("source", "severity", "message")
MAX_MESSAGE_LENGTH = 4096
FAULT_MODES = ("none", "errors", "latency", "memory_leak")
# Client-supplied request IDs are echoed into logs, so only accept a safe charset (no log injection).
REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")

log = logging.getLogger("secure_event_api")


def load_config() -> dict:
    return {
        "version": os.getenv("APP_VERSION", "dev"),
        "commit": os.getenv("GIT_COMMIT", "unknown"),
        "archive_bucket": os.getenv("ARCHIVE_BUCKET", ""),
        "archive_prefix": os.getenv("ARCHIVE_PREFIX", "events"),
        "fault_mode": os.getenv("FAULT_MODE", "none"),
        "fault_error_rate": float(os.getenv("FAULT_ERROR_RATE", "0.5")),
        "fault_latency_seconds": float(os.getenv("FAULT_LATENCY_SECONDS", "1.5")),
        "fault_leak_bytes": int(os.getenv("FAULT_LEAK_BYTES", str(1024 * 1024))),
    }


class S3Archiver:
    """Writes each accepted event to s3://<bucket>/<prefix>/YYYY/MM/DD/<id>.json."""

    def __init__(self, bucket: str, prefix: str = "events"):
        import boto3  # imported lazily so local dev and tests don't need AWS libs

        self._client = boto3.client("s3")
        self._bucket = bucket
        self._prefix = prefix

    def archive(self, event: dict) -> None:
        now = datetime.now(UTC)
        key = f"{self._prefix}/{now:%Y/%m/%d}/{event['id']}.json"
        self._client.put_object(
            Bucket=self._bucket,
            Key=key,
            Body=json.dumps(event).encode("utf-8"),
            ContentType="application/json",
        )


def resolve_request_id(incoming: str) -> str:
    # fullmatch, not match: `$` also matches before a trailing newline, which would let "id\n" through.
    return incoming if REQUEST_ID_PATTERN.fullmatch(incoming) else str(uuid.uuid4())


def validate_event(payload) -> list[str]:
    if not isinstance(payload, dict):
        return ["body must be a JSON object"]
    errors = [f"missing field: {f}" for f in REQUIRED_FIELDS if not payload.get(f)]
    severity = payload.get("severity")
    if severity and severity not in VALID_SEVERITIES:
        errors.append(f"severity must be one of {', '.join(VALID_SEVERITIES)}")
    message = payload.get("message")
    if message is not None and not isinstance(message, str):
        errors.append("message must be a string")
    elif message and len(message) > MAX_MESSAGE_LENGTH:
        errors.append(f"message exceeds {MAX_MESSAGE_LENGTH} characters")
    attributes = payload.get("attributes", {})
    if not isinstance(attributes, dict):
        errors.append("attributes must be an object")
    return errors


def create_app(config: dict | None = None, archiver=None) -> Flask:
    cfg = load_config()
    cfg.update(config or {})
    if cfg["fault_mode"] not in FAULT_MODES:
        raise ValueError(f"FAULT_MODE must be one of {FAULT_MODES}")

    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(message)s")
    app = Flask(__name__)

    registry = CollectorRegistry()
    requests_total = Counter(
        "http_requests_total", "HTTP requests", ["method", "endpoint", "status"], registry=registry
    )
    request_latency = Histogram(
        "http_request_duration_seconds",
        "HTTP request latency",
        ["method", "endpoint"],
        buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5),
        registry=registry,
    )
    events_total = Counter(
        "events_ingested_total", "Accepted security events", ["severity"], registry=registry
    )
    archive_failures = Counter(
        "events_archive_failures_total", "Events that could not be archived", registry=registry
    )
    build_info = Gauge(
        "app_build_info", "Build metadata", ["version", "commit", "fault_mode"], registry=registry
    )
    build_info.labels(cfg["version"], cfg["commit"], cfg["fault_mode"]).set(1)

    if archiver is None and cfg["archive_bucket"]:
        archiver = S3Archiver(cfg["archive_bucket"], cfg["archive_prefix"])

    stats = {severity: 0 for severity in VALID_SEVERITIES}
    leak: list[bytearray] = []
    app.extensions["fault_leak"] = leak

    @app.before_request
    def _start_timer():
        g.start = time.perf_counter()
        g.request_id = resolve_request_id(request.headers.get("X-Request-ID", ""))

    @app.after_request
    def _record_metrics(response):
        endpoint = request.url_rule.rule if request.url_rule else "unmatched"
        if endpoint != "/metrics":
            elapsed = time.perf_counter() - g.get("start", time.perf_counter())
            request_latency.labels(request.method, endpoint).observe(elapsed)
            requests_total.labels(request.method, endpoint, str(response.status_code)).inc()
        if "request_id" in g:
            response.headers["X-Request-ID"] = g.request_id
        return response

    @app.get("/healthz")
    def healthz():
        return jsonify(status="ok")

    @app.get("/readyz")
    def readyz():
        return jsonify(status="ready", archiving=archiver is not None)

    @app.get("/version")
    def version():
        return jsonify(version=cfg["version"], commit=cfg["commit"])

    @app.get("/metrics")
    def metrics():
        return Response(generate_latest(registry), mimetype=CONTENT_TYPE_LATEST)

    @app.post("/v1/events")
    def ingest_event():
        fault = cfg["fault_mode"]
        if fault == "errors" and random.random() < cfg["fault_error_rate"]:
            return jsonify(error="internal error"), 500
        if fault == "latency":
            time.sleep(cfg["fault_latency_seconds"])
        if fault == "memory_leak":
            leak.append(bytearray(b"\xab" * cfg["fault_leak_bytes"]))

        payload = request.get_json(silent=True)
        errors = validate_event(payload)
        if errors:
            return jsonify(errors=errors), 400

        event = {
            "id": str(uuid.uuid4()),
            "received_at": datetime.now(UTC).isoformat(),
            "source": payload["source"],
            "severity": payload["severity"],
            "message": payload["message"],
            "attributes": payload.get("attributes", {}),
        }
        if archiver is not None:
            try:
                archiver.archive(event)
            except Exception:
                archive_failures.inc()
                log.exception(
                    json.dumps({"msg": "archive failed", "event_id": event["id"], "request_id": g.request_id})
                )
                return jsonify(error="archive unavailable, retry later"), 503

        stats[event["severity"]] += 1
        events_total.labels(event["severity"]).inc()
        log.info(
            json.dumps(
                {
                    "msg": "event accepted",
                    "id": event["id"],
                    "severity": event["severity"],
                    "request_id": g.request_id,
                }
            )
        )
        return jsonify(id=event["id"]), 201

    @app.get("/v1/events/stats")
    def event_stats():
        return jsonify(total=sum(stats.values()), by_severity=stats)

    return app
