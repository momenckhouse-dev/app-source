import pytest

from secure_event_api.app import create_app, validate_event

VALID_EVENT = {"source": "fw-gw-01", "severity": "high", "message": "Blocked outbound C2 beacon"}


class FakeArchiver:
    def __init__(self, fail=False):
        self.fail = fail
        self.events = []

    def archive(self, event):
        if self.fail:
            raise RuntimeError("s3 unavailable")
        self.events.append(event)


@pytest.fixture
def client():
    return create_app({"fault_mode": "none", "archive_bucket": ""}).test_client()


def test_health_and_readiness(client):
    assert client.get("/healthz").get_json() == {"status": "ok"}
    assert client.get("/readyz").get_json()["status"] == "ready"


def test_version_reports_build_metadata():
    app = create_app({"version": "1.2.3", "commit": "abc123", "archive_bucket": ""})
    assert app.test_client().get("/version").get_json() == {"version": "1.2.3", "commit": "abc123"}


def test_accepts_valid_event_and_updates_stats(client):
    response = client.post("/v1/events", json=VALID_EVENT)
    assert response.status_code == 201
    assert "id" in response.get_json()
    stats = client.get("/v1/events/stats").get_json()
    assert stats["total"] == 1
    assert stats["by_severity"]["high"] == 1


@pytest.mark.parametrize(
    "payload, expected",
    [
        ({}, "missing field: source"),
        ({**VALID_EVENT, "severity": "urgent"}, "severity must be one of"),
        ({**VALID_EVENT, "message": "x" * 5000}, "message exceeds"),
        ({**VALID_EVENT, "attributes": []}, "attributes must be an object"),
        (["not", "an", "object"], "body must be a JSON object"),
    ],
)
def test_validation_errors(payload, expected):
    assert any(expected in error for error in validate_event(payload))


def test_rejects_invalid_event(client):
    response = client.post("/v1/events", json={"source": "x"})
    assert response.status_code == 400
    assert client.get("/v1/events/stats").get_json()["total"] == 0


def test_rejects_non_json_body(client):
    response = client.post("/v1/events", data="not json", content_type="text/plain")
    assert response.status_code == 400


def test_archives_accepted_events():
    archiver = FakeArchiver()
    client = create_app({"archive_bucket": ""}, archiver=archiver).test_client()
    client.post("/v1/events", json=VALID_EVENT)
    assert len(archiver.events) == 1
    assert archiver.events[0]["source"] == "fw-gw-01"


def test_archive_failure_returns_503_and_is_counted():
    client = create_app({"archive_bucket": ""}, archiver=FakeArchiver(fail=True)).test_client()
    assert client.post("/v1/events", json=VALID_EVENT).status_code == 503
    metrics = client.get("/metrics").get_data(as_text=True)
    assert "events_archive_failures_total 1.0" in metrics


def test_metrics_expose_request_counters_and_build_info():
    client = create_app({"version": "9.9.9", "commit": "deadbeef", "archive_bucket": ""}).test_client()
    client.post("/v1/events", json=VALID_EVENT)
    metrics = client.get("/metrics").get_data(as_text=True)
    assert 'http_requests_total{endpoint="/v1/events",method="POST",status="201"} 1.0' in metrics
    assert 'events_ingested_total{severity="high"} 1.0' in metrics
    assert 'app_build_info{commit="deadbeef",fault_mode="none",version="9.9.9"} 1.0' in metrics
    assert "http_request_duration_seconds_bucket" in metrics


def test_fault_mode_errors_returns_500():
    client = create_app({"fault_mode": "errors", "fault_error_rate": 1.0, "archive_bucket": ""}).test_client()
    assert client.post("/v1/events", json=VALID_EVENT).status_code == 500


def test_fault_mode_memory_leak_retains_memory():
    app = create_app({"fault_mode": "memory_leak", "fault_leak_bytes": 1024, "archive_bucket": ""})
    client = app.test_client()
    for _ in range(3):
        client.post("/v1/events", json=VALID_EVENT)
    assert len(app.extensions["fault_leak"]) == 3


def test_unknown_fault_mode_is_rejected():
    with pytest.raises(ValueError):
        create_app({"fault_mode": "chaos"})
