"""
OIP Backend — Step 4 (checkpoint 1): Massive (formerly Polygon.io) connection

Auth (Step 2) and persistence (Step 3) are unchanged. This checkpoint
adds one thing: /api/market-check, a protected route that proves the
app can reach real market data — before any real logic (Opportunity
Score's discovery drivers, real chain pricing) gets built on top of a
connection that hasn't been verified yet. Same pattern as /api/db-check
in Step 3.

Env vars needed — set in Render's dashboard, never committed to GitHub:
  APP_PASSWORD_HASH   - output of hash_password(), see the bottom of
                        this file for the one-time generator
  SECRET_KEY          - random string used to sign session cookies
  DATABASE_URL        - Postgres connection string
  MASSIVE_API_KEY     - from your massive.com dashboard (added this
                        checkpoint) — Polygon.io rebranded to Massive
                        in Oct 2025, same data, same API shape

The app refuses to start if any of these are missing, on purpose — a
silent insecure or broken fallback is worse than a loud failure at
deploy time.
"""

import os
import hmac
import hashlib
import secrets
import urllib.request
import urllib.error
import json
import math
from datetime import date, timedelta

from fastapi import FastAPI, Request, HTTPException, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from sqlalchemy import text
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional

from database import get_db, engine
import models
from seed_data import SEED_OPPORTUNITIES, SEED_JOURNAL_ENTRIES

SECRET_KEY = os.environ.get("SECRET_KEY")
APP_PASSWORD_HASH = os.environ.get("APP_PASSWORD_HASH")
MASSIVE_API_KEY = os.environ.get("MASSIVE_API_KEY")

if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY environment variable is not set. Set it in Render's Environment tab.")
if not APP_PASSWORD_HASH:
    raise RuntimeError("APP_PASSWORD_HASH environment variable is not set. Set it in Render's Environment tab.")
if not MASSIVE_API_KEY:
    raise RuntimeError("MASSIVE_API_KEY environment variable is not set. Set it in Render's Environment tab.")

COOKIE_NAME = "oip_session"
SESSION_MAX_AGE = 60 * 60 * 24 * 14  # 14 days

serializer = URLSafeTimedSerializer(SECRET_KEY)

app = FastAPI(title="OIP Backend")


@app.on_event("startup")
def create_tables():
    # Idempotent — creates tables if they don't exist, does nothing if
    # they already do. Fine at this scale; a real migration tool
    # (Alembic) is a later refinement if the schema needs to evolve
    # without risking existing data.
    models.Base.metadata.create_all(bind=engine)


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
def root(request: Request):
    if get_session(request):
        return RedirectResponse(url="/app")
    return RedirectResponse(url="/login")


@app.get("/app", response_class=HTMLResponse)
def serve_app(request: Request):
    if not get_session(request):
        return RedirectResponse(url="/login")
    with open(os.path.join(os.path.dirname(__file__), "frontend.html"), encoding="utf-8") as f:
        return f.read()


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
    response = RedirectResponse(url="/app", status_code=303)
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


@app.get("/api/tables-check")
def tables_check(session: dict = Depends(require_auth), db: Session = Depends(get_db)):
    """Queries Postgres's own catalog to confirm the tables genuinely
    exist — not just that create_all() ran without raising."""
    result = db.execute(text(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name"
    ))
    tables = [row[0] for row in result]
    return {"tables": tables}


@app.get("/api/market-check")
def market_check(session: dict = Depends(require_auth)):
    """Proves the app can reach real market data — the first real test
    of whether anything downstream (Opportunity Score, real chain
    pricing) has real ground to stand on. Uses stdlib urllib rather
    than a new dependency, since this is deliberately the simplest
    possible real call: previous day's close for one ticker."""
    url = f"https://api.massive.com/v2/aggs/ticker/AAPL/prev?adjusted=true&apiKey={MASSIVE_API_KEY}"
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            payload = json.loads(response.read())
        return {"connected": True, "sample": payload}
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        raise HTTPException(status_code=502, detail=f"Massive API returned {e.code}: {body}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Could not reach Massive API: {str(e)}")


@app.get("/api/hv-check/{ticker}")
def hv_check(ticker: str, session: dict = Depends(require_auth)):
    """Computes real historical volatility from real daily closes —
    standard deviation of log returns, annualized. No options data
    needed for this half; implied volatility (the other half of the
    IV-vs-HV spread) needs the separate Massive Options subscription,
    not wired in yet."""
    end = date.today()
    start = end - timedelta(days=60)
    url = (f"https://api.massive.com/v2/aggs/ticker/{ticker.upper()}/range/1/day/"
           f"{start.isoformat()}/{end.isoformat()}?adjusted=true&sort=asc&apiKey={MASSIVE_API_KEY}")
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            payload = json.loads(response.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        raise HTTPException(status_code=502, detail=f"Massive API returned {e.code}: {body}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Could not reach Massive API: {str(e)}")

    results = payload.get("results", [])
    if len(results) < 10:
        raise HTTPException(status_code=502, detail=f"Not enough price history returned ({len(results)} days) to compute HV")

    closes = [bar["c"] for bar in results]
    log_returns = [math.log(closes[i] / closes[i - 1]) for i in range(1, len(closes))]
    n = len(log_returns)
    mean_return = sum(log_returns) / n
    variance = sum((r - mean_return) ** 2 for r in log_returns) / (n - 1)
    daily_stdev = math.sqrt(variance)
    annualized_hv_pct = daily_stdev * math.sqrt(252) * 100

    return {
        "ticker": ticker.upper(),
        "tradingDaysUsed": len(closes),
        "lastClose": closes[-1],
        "historicalVolatilityPct": round(annualized_hv_pct, 2),
        "note": "Real HV from real price history. This is half of the IV-vs-HV spread — implied volatility still needs the separate Options subscription."
    }


def _fetch_json(url):
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        raise HTTPException(status_code=502, detail=f"Massive API returned {e.code}: {body}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Could not reach Massive API: {str(e)}")


def find_atm_near_term_iv(results, today, min_days_out=5):
    """Given a list of option contracts (Massive's chain snapshot shape),
    picks the nearest expiration at least min_days_out away, then the
    strike closest to the underlying's current price at that expiration.
    Tested against a synthetic version of Massive's documented response
    shape before ever touching the live endpoint."""
    underlying_price = None
    for r in results:
        price = r.get("underlying_asset", {}).get("price")
        if price:
            underlying_price = price
            break
    if underlying_price is None:
        return None

    candidates = []
    for r in results:
        exp_str = r.get("details", {}).get("expiration_date")
        iv = r.get("implied_volatility")
        strike = r.get("details", {}).get("strike_price")
        if not exp_str or iv is None or strike is None:
            continue
        exp_date = date.fromisoformat(exp_str)
        if (exp_date - today).days >= min_days_out:
            candidates.append((exp_date, r))
    if not candidates:
        return None

    nearest_exp = min(c[0] for c in candidates)
    same_exp = [r for exp, r in candidates if exp == nearest_exp]
    atm = min(same_exp, key=lambda r: abs(r["details"]["strike_price"] - underlying_price))
    return {
        "underlyingPrice": underlying_price,
        "expiration": nearest_exp.isoformat(),
        "strike": atm["details"]["strike_price"],
        "impliedVolatilityPct": round(atm["implied_volatility"] * 100, 2)
    }


@app.get("/api/iv-check/{ticker}")
def iv_check(ticker: str, session: dict = Depends(require_auth)):
    """Pulls the real options chain and extracts IV from the nearest
    at-the-money, near-term contract — the standard practical proxy
    for 'current IV level' without needing a full vol surface."""
    url = f"https://api.massive.com/v3/snapshot/options/{ticker.upper()}?contract_type=call&limit=250&apiKey={MASSIVE_API_KEY}"
    payload = _fetch_json(url)
    results = payload.get("results", [])
    if not results:
        raise HTTPException(status_code=502, detail=f"No options contracts returned for {ticker.upper()}")

    match = find_atm_near_term_iv(results, date.today())
    if not match:
        raise HTTPException(status_code=502, detail="Could not find a suitable near-term, at-the-money contract")

    return {"ticker": ticker.upper(), **match}


@app.get("/api/vol-bias-check/{ticker}")
def vol_bias_check(ticker: str, session: dict = Depends(require_auth)):
    """The real version of the IV-vs-HV spread we settled on for
    Volatility Bias — both halves pulled from real Massive data in one
    call. High IV rich vs. HV -> Short Vol lean; cheap -> Long Vol."""
    hv_result = hv_check(ticker, session)
    iv_url = f"https://api.massive.com/v3/snapshot/options/{ticker.upper()}?contract_type=call&limit=250&apiKey={MASSIVE_API_KEY}"
    iv_payload = _fetch_json(iv_url)
    iv_results = iv_payload.get("results", [])
    iv_match = find_atm_near_term_iv(iv_results, date.today()) if iv_results else None
    if not iv_match:
        raise HTTPException(status_code=502, detail=f"Could not compute IV for {ticker.upper()}")

    hv_pct = hv_result["historicalVolatilityPct"]
    iv_pct = iv_match["impliedVolatilityPct"]
    spread = round(iv_pct - hv_pct, 2)
    if spread > 3:
        bias = "Short Vol"
    elif spread < -3:
        bias = "Long Vol"
    else:
        bias = "Neutral"

    return {
        "ticker": ticker.upper(),
        "historicalVolatilityPct": hv_pct,
        "impliedVolatilityPct": iv_pct,
        "spread": spread,
        "volBias": bias
    }


@app.post("/api/seed")
def seed(session: dict = Depends(require_auth), db: Session = Depends(get_db)):
    """One-time seed of the same mock data the frontend already trusts.
    Idempotent — does nothing if opportunities already exist, so it's
    safe to call more than once (e.g. after a redeploy)."""
    existing = db.query(models.Opportunity).count()
    if existing > 0:
        return {"seeded": False, "reason": "opportunities table already has data", "count": existing}

    for opp in SEED_OPPORTUNITIES:
        db.add(models.Opportunity(**opp))
    for entry in SEED_JOURNAL_ENTRIES:
        db.add(models.JournalEntry(**entry))
    db.commit()
    return {"seeded": True, "opportunities": len(SEED_OPPORTUNITIES), "journal_entries": len(SEED_JOURNAL_ENTRIES)}


@app.get("/api/opportunities")
def list_opportunities(session: dict = Depends(require_auth), db: Session = Depends(get_db)):
    opps = db.query(models.Opportunity).all()
    return [
        {
            "id": o.id, "sector": o.sector, "status": o.status,
            "opportunityScore": o.opportunity_score, "volatilityScore": o.volatility_score,
            "volBias": o.vol_bias, "ivRank": o.iv_rank, "directionalLean": o.directional_lean,
            "suggestedTrade": o.suggested_trade, "thesis": o.thesis, "notes": o.notes,
            "pendingAnalysis": o.pending_analysis,
        }
        for o in opps
    ]


@app.get("/api/journal")
def list_journal(session: dict = Depends(require_auth), db: Session = Depends(get_db)):
    entries = db.query(models.JournalEntry).all()
    return [
        {
            "id": e.id, "ticker": e.ticker, "sector": e.sector, "loggedDate": e.logged_date,
            "statusAtLog": e.status_at_log, "opportunityScore": e.opportunity_score,
            "volatilityScore": e.volatility_score, "tradeQualityComposite": e.trade_quality_composite,
            "convictionComposite": e.conviction_composite, "structure": e.structure,
            "outcome": e.outcome, "realizedPnL": e.realized_pnl, "lessonsLearned": e.lessons_learned,
            "regimeAtLog": e.regime_at_log, "daysToCatalystAtLog": e.days_to_catalyst_at_log,
        }
        for e in entries
    ]


class OpportunityUpdate(BaseModel):
    status: Optional[str] = None
    notes: Optional[str] = None


@app.patch("/api/opportunities/{opp_id}")
def update_opportunity(opp_id: str, update: OpportunityUpdate,
                        session: dict = Depends(require_auth), db: Session = Depends(get_db)):
    """Persists the two things the frontend actually lets someone edit
    right now — status and notes. Everything else an opportunity shows
    (scores, driver breakdowns, trade construction) is still computed
    fresh client-side each load, not round-tripped through here yet."""
    opp = db.query(models.Opportunity).filter(models.Opportunity.id == opp_id).first()
    if not opp:
        raise HTTPException(status_code=404, detail=f"No opportunity with id {opp_id}")
    if update.status is not None:
        opp.status = update.status
    if update.notes is not None:
        opp.notes = update.notes
    db.commit()
    return {"updated": True, "id": opp_id, "status": opp.status, "notes": opp.notes}


class JournalEntryIn(BaseModel):
    id: str
    oppId: str = ""
    ticker: str
    sector: str = ""
    loggedDate: str = ""
    statusAtLog: str = ""
    opportunityScore: Optional[int] = None
    volatilityScore: Optional[int] = None
    tradeQualityComposite: Optional[int] = None
    convictionComposite: Optional[int] = None
    structure: str = ""
    thesis: str = ""
    rationale: str = ""
    outcome: str = ""
    realizedPnL: str = ""
    lessonsLearned: str = ""
    regimeAtLog: Optional[str] = None
    daysToCatalystAtLog: Optional[int] = None


@app.post("/api/journal")
def upsert_journal_entry(entry: JournalEntryIn,
                          session: dict = Depends(require_auth), db: Session = Depends(get_db)):
    """Create or update — matches the frontend's existing behavior of
    re-saving the same entry (e.g. adding Lessons Learned later)."""
    existing = db.query(models.JournalEntry).filter(models.JournalEntry.id == entry.id).first()
    target = existing or models.JournalEntry(id=entry.id)

    target.opp_id = entry.oppId
    target.ticker = entry.ticker
    target.sector = entry.sector
    target.logged_date = entry.loggedDate
    target.status_at_log = entry.statusAtLog
    target.opportunity_score = entry.opportunityScore
    target.volatility_score = entry.volatilityScore
    target.trade_quality_composite = entry.tradeQualityComposite
    target.conviction_composite = entry.convictionComposite
    target.structure = entry.structure
    target.thesis = entry.thesis
    target.rationale = entry.rationale
    target.outcome = entry.outcome
    target.realized_pnl = entry.realizedPnL
    target.lessons_learned = entry.lessonsLearned
    target.regime_at_log = entry.regimeAtLog
    target.days_to_catalyst_at_log = entry.daysToCatalystAtLog

    if not existing:
        db.add(target)
    db.commit()
    return {"saved": True, "id": entry.id, "created": existing is None}


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
