import os

import pyotp
import pytest

SECRET = pyotp.random_base32()
os.environ["DEMO_MFA_SECRET"] = SECRET

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402

client = TestClient(main.app)
EMAIL = "user@enterprise.com"


@pytest.fixture(autouse=True)
def reset_state():
    main.FAILED_ATTEMPTS.clear()
    main.LAST_USED_STEP.clear()


def post(code, email=EMAIL):
    return client.post("/verify-mfa", json={"email": email, "otp_code": code})


def test_valid_code_grants_access():
    assert post(pyotp.TOTP(SECRET).now()).status_code == 200


def test_replayed_code_is_rejected():
    code = pyotp.TOTP(SECRET).now()
    assert post(code).status_code == 200
    assert post(code).status_code == 401


def test_wrong_code_is_rejected():
    assert post("000000").status_code == 401


def test_unknown_email_looks_like_wrong_code():
    wrong = post("000000")
    unknown = post("000000", email="nobody@enterprise.com")
    assert unknown.status_code == wrong.status_code
    assert unknown.json() == wrong.json()


def test_non_numeric_code_is_rejected():
    assert post("abcdef").status_code == 401


def test_lockout_after_five_failures():
    for _ in range(main.MAX_ATTEMPTS):
        post("000000")
    assert post(pyotp.TOTP(SECRET).now()).status_code == 429
