"""
OIP Backend — Step 3 (checkpoint 1): database connection

Auth from Step 2 is unchanged. This checkpoint adds one thing on top:
/api/db-check, a protected route that proves the app can actually
reach a real Postgres database — before any real tables or CRUD logic
get built on top of a connection we haven't verified yet.

Env vars needed — set in Render's dashboard, never committed to GitHub:
  APP_PASSWORD_HASH   - output of hash_password(), see the bottom of
                        this file for the one-time generator
  SECRET_KEY          - random string used to sign session cookies
  DATABASE_URL        - Postgres connection string, from Render's
                        Postgres dashboard (added this checkpoint)

The app refuses to start if any of these are missing, on purpose — a
silent insecure or broken fallback is worse than a loud failure at
deploy time.
"""

import os
import hmac
import hashlib
import secrets

from fastapi import FastAPI, Request, HTTPException, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from sqlalchemy import text
from sqlalchemy.orm import Session

from database import get_db

SECRET_KEY = os.environ.get("SECRET_KEY")
APP_PASSWORD_HASH = os.environ.get("APP_PASSWORD_HASH")

if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY environment variable is not set. Set it in Render's Environment tab.")
if not APP_PASSWORD_HASH:
    raise RuntimeError("APP_PASSWORD_HASH environment variable is not set. Set it in Render's Environment tab.")

COOKIE_NAME = "oip_session"
SESSION_MAX_AGE = 60 * 60 * 24 * 14  # 14 days

serializer = URLSafeTimedSerializer(SECRET_KEY)

app = FastAPI(title="OIP Backend")


def hash_password(password: str) -> str:
    """Used once, offline, to produce APP_PASSWORD_HASH. The running
    app never calls this — it only verifies, since there's no signup
    flow, just one shared password set via environment variable."""
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 260000)
    return f"pbkdf2_sha256$260000${salt}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algo, iterations, salt, digest_hex = stored_hash.split("$")
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iterations))
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def get_session(request: Request):
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    try:
        return serializer.loads(token, max_age=SESSION_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return None


def require_auth(request: Request):
    session = get_session(request)
    if not session:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return session


@app.get("/health")
def health():
    return {"status": "ok", "service": "oip-backend", "step": 3}


@app.get("/", response_class=HTMLResponse)
def root():
    return "<p>OIP backend is running. Go to <a href='/login'>/login</a> to sign in.</p>"


LOGIN_PAGE = """
<!DOCTYPE html>
<html>
<head><title>OIP Login</title></head>
<body style="font-family: sans-serif; max-width: 360px; margin: 80px auto;">
  <h2>OIP</h2>
  {message}
  <form method="post" action="/login">
    <input type="password" name="password" placeholder="Password"
           style="width:100%; padding:8px; margin-bottom:10px; box-sizing:border-box;" autofocus>
    <button type="submit" style="width:100%; padding:8px;">Log in</button>
  </form>
</body>
</html>
"""


@app.get("/login", response_class=HTMLResponse)
def login_form():
    return LOGIN_PAGE.format(message="")


@app.post("/login")
def login(password: str = Form(...)):
    if not verify_password(password, APP_PASSWORD_HASH):
        return HTMLResponse(
            LOGIN_PAGE.format(message="<p style='color:red;'>Wrong password.</p>"),
            status_code=401,
        )
    token = serializer.dumps({"user": "owner"})
    response = RedirectResponse(url="/api/me", status_code=303)
    response.set_cookie(
        key=COOKIE_NAME, value=token, max_age=SESSION_MAX_AGE,
        httponly=True, secure=True, samesite="lax",
    )
    return response


@app.post("/logout")
def logout():
    response = JSONResponse({"logged_out": True})
    response.delete_cookie(COOKIE_NAME)
    return response


@app.get("/api/me")
def me(session: dict = Depends(require_auth)):
    return {"authenticated": True, "step": 3}


@app.get("/api/db-check")
def db_check(session: dict = Depends(require_auth), db: Session = Depends(get_db)):
    """Proves the app can actually reach Postgres — not just that the
    code imports cleanly. Runs a trivial query and returns its result."""
    result = db.execute(text("SELECT 1")).scalar()
    return {"db_connected": True, "result": result}


# ---------------------------------------------------------------
# One-time hash generator — not used by the running app.
# Run locally (or ask Claude to run it) to produce APP_PASSWORD_HASH
# for a given password, then paste the result into Render as an
# environment variable. The plaintext password itself never needs to
# be stored anywhere after this.
# ---------------------------------------------------------------
if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        print(hash_password(sys.argv[1]))
    else:
        print("Usage: python main.py <password-to-hash>")
