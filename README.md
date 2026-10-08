MFA Gateway

A FastAPI service that verifies TOTP (time-based one-time password) codes, the kind used by Google Authenticator. It was built as my thesis project, a Zero Trust policy enforcement point that checks a second factor before access is granted.

Stack: Python, FastAPI, PyOTP, Pydantic, pytest

What it does

Verifies 6-digit TOTP codes through POST /verify-mfa
Locks an account for 5 minutes after 5 failed attempts
Rejects a code that has already been used
Returns the same response for an unknown email and a wrong code, so attackers can't find out which accounts exist
Covered by 6 automated tests (pytest)
Setup & Usage
Files
main.py — the MFA verification server
setup_mfa.py — generates a secret + QR code for enrolling a new user
requirements.txt — exact dependencies needed to run this project
test_main.py — automated tests (pytest)
mfa_qr_code.png — generated locally by setup_mfa.py (not committed); scan it with an authenticator app

1. Set up a virtual environment

In the project folder, open a terminal:

bash
python -m venv venv

Activate it:

Windows: venv\Scripts\activate
Mac/Linux: source venv/bin/activate

2. Install dependencies
bash
pip install -r requirements.txt

3. Set the secret as an environment variable

The secret must match the one used to generate mfa_qr_code.png (printed by setup_mfa.py when it was run). It is not hardcoded in main.py — it's read from an environment variable so it never sits in source control.

Windows (PowerShell):

powershell
$env:DEMO_MFA_SECRET="<your secret here>"

Windows (cmd):

set DEMO_MFA_SECRET=your-secret

Mac/Linux:

bash
export DEMO_MFA_SECRET="<your secret here>"

Set this in the same terminal window you'll launch the server from — it does not persist across new terminal sessions.

4. Run the server
bash
uvicorn main:app --reload

Server runs at http://127.0.0.1:8000.

5. Test it

Go to http://127.0.0.1:8000/docs, expand POST /verify-mfa, click "Try it out", and enter:

json
{
  "email": "user@enterprise.com",
  "otp_code": "123456"
}

(use the real, current 6-digit code from an authenticator app scanned against mfa_qr_code.png)

Or via curl:

bash
curl -X POST http://127.0.0.1:8000/verify-mfa \
  -H "Content-Type: application/json" \
  -d '{"email":"user@enterprise.com","otp_code":"123456"}'
6. Run the tests
bash
pytest
Security features implemented (and tested)
Rate limiting / lockout — 5 failed attempts within 5 minutes locks the account and returns 429 Too many failed attempts. Verified by submitting 6 consecutive wrong codes.
Replay protection — a code that has already been redeemed once is rejected on reuse, even if it's still inside its 30-second validity window. Verified by resubmitting a just-accepted code and getting 401.
Uniform failure responses — an unknown email and a wrong code both return the same 401 status and message, so the API can't be used to enumerate which accounts exist.
Clock drift tolerance — codes are accepted within a ±30s window (valid_window=1) to account for minor clock skew between server and phone.
Input validation — the OTP field must be exactly 6 digits before it's passed to the verification step.
Known limitations (by design, for this scope)
USER_DB, FAILED_ATTEMPTS, and the replay-tracking dict are in-memory Python dictionaries — they reset on server restart and would not work across multiple server instances. A production deployment would back these with a real database and Redis (or similar) instead.
The server runs over plain HTTP for local development; a production deployment would require HTTPS/TLS termination in front of it.
This endpoint verifies the MFA step only, in isolation — it assumes a user has already been authenticated by a first factor (e.g. password) elsewhere in a real system.
