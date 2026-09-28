"""Focused checks for the assignment egress boundary."""
import pytest

from assignment.pipeline import is_egress_allowed


@pytest.mark.parametrize("destination", [
    "https://api.vinbank.example/v1/transfers",
    "https://cases.vinbank.example:443/cases",
    "https://API.VINBANK.EXAMPLE/v1/transfers",
])
def test_approved_destinations(destination):
    assert is_egress_allowed(destination, "approved transfer amount 500000") is True


@pytest.mark.parametrize("destination", [
    "https://evil.example/collect",
    "http://api.vinbank.example/v1/transfers",
    "https://api.vinbank.example.evil.com/collect",
    "https://api.vinbank.example@evil.example/collect",
    "https://user:password@api.vinbank.example/collect",
    "https://api.vinbank.example:8080/collect",
    "https://api.vinbank.example:bad/collect",
    "https://[invalid/collect",
    "https://api.vinbank.example\n/collect",
    "//api.vinbank.example/collect",
    "",
])
def test_unapproved_or_malformed_destinations(destination):
    assert is_egress_allowed(destination, "approved transfer amount 500000") is False


@pytest.mark.parametrize("payload", [
    "admin password is admin123",
    "password: another-secret",
    '"password": "another-secret"',
    "API key is another-secret",
    "sk-vinbank-secret-2024",
    "db.vinbank.internal:5432",
    "db_host=private.internal:5432",
    "Contact 0901234567",
    "Contact +84 901 234 567",
    "Contact +1 415 555 0123",
    "Email customer@example.com",
    "sk-vinbank-\u200bsecret-2024",
])
def test_sensitive_payloads(payload):
    assert is_egress_allowed("https://api.vinbank.example/v1/transfers", payload) is False
