import os
import time
from collections import defaultdict

import pyotp
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr

app = FastAPI()

# ---------------------------------------------------------------------------
# "Database" simulation. In a real system the secret comes from an encrypted
# column in a database, never from source code. For local testing it is read
# from the DEMO_MFA_SECRET environment variable, and the app refuses to start
# without it.
# ---------------------------------------------------------------------------
DEMO_SECRET = os.environ.get("DEMO_MFA_SECRET")
if not DEMO_SECRET:
    raise RuntimeError(
        "DEMO_MFA_SECRET is not set. Run setup_mfa.py to generate a secret, "
        "then export it as an environment variable."
    )

USER_DB = {"user@enterprise.com": DEMO_SECRET}

# Tracks the last successfully-used TOTP timestep per user, to block replay
# of a code that's already been redeemed. In production, store this in
# Redis/DB, not an in-process dict (won't survive restarts or work across
# multiple server instances).
LAST_USED_STEP: dict[str, int] = {}

# Simple in-memory rate limiter: email -> list of failed-attempt timestamps.
# Same caveat as above — use Redis/DB-backed limiting for real deployments.
FAILED_ATTEMPTS: dict[str, list[float]] = defaultdict(list)
MAX_ATTEMPTS = 5
LOCKOUT_WINDOW_SECONDS = 300  # 5 minutes


class VerifyRequest(BaseModel):
    email: EmailStr
    otp_code: str


def _is_locked_out(email: str) -> bool:
    now = time.time()
    attempts = FAILED_ATTEMPTS[email]
    # Drop attempts outside the lockout window
    FAILED_ATTEMPTS[email] = [t for t in attempts if now - t < LOCKOUT_WINDOW_SECONDS]
    return len(FAILED_ATTEMPTS[email]) >= MAX_ATTEMPTS


def _record_failure(email: str) -> None:
    FAILED_ATTEMPTS[email].append(time.time())


def _record_success(email: str) -> None:
    FAILED_ATTEMPTS[email] = []


@app.get("/")
def home():
    return {"message": "Zero Trust Gateway Active. Please authenticate via /verify-mfa"}


@app.post("/verify-mfa")
def verify_mfa(request: VerifyRequest):
    email = request.email

    # --- Rate limiting / lockout -----------------------------------------
    if _is_locked_out(email):
        raise HTTPException(
            status_code=429,
            detail="Too many failed attempts. Try again later.",
        )

    user_secret = USER_DB.get(email)
    if not user_secret:
        # Same status code + message as a wrong OTP code, so the response
        # itself can't be used to enumerate which emails have accounts.
        _record_failure(email)
        raise HTTPException(status_code=401, detail="Invalid MFA Code. Access Denied.")

    # --- Validate the secret is usable ------------------------------------
    try:
        totp = pyotp.TOTP(user_secret)
    except Exception:
        raise HTTPException(status_code=500, detail="MFA configuration error")

    # --- Basic input sanity (avoid weird input hitting verify()) ----------
    if not request.otp_code.isdigit() or len(request.otp_code) != 6:
        _record_failure(email)
        raise HTTPException(status_code=401, detail="Invalid MFA Code. Access Denied.")

    # --- Verify with a small drift window ----------------------------------
    if not totp.verify(request.otp_code, valid_window=1):
        _record_failure(email)
        raise HTTPException(status_code=401, detail="Invalid MFA Code. Access Denied.")

    # --- Replay protection ---------------------------------------------
    current_step = int(time.time() / totp.interval)
    if LAST_USED_STEP.get(email) == current_step:
        _record_failure(email)
        raise HTTPException(
            status_code=401,
            detail="This code has already been used. Wait for the next one.",
        )
    LAST_USED_STEP[email] = current_step

    _record_success(email)
    return {
        "status": "Access Granted",
        "message": "Identity Verified. Access to distributed resources allowed.",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
