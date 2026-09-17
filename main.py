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
  FINNHUB_API_KEY     - from your finnhub.io dashboard — free tier,
                        used only for real Catalyst Strength data
                        (next-earnings date/timing). Massive's own
                        earnings feed (Benzinga partner data) is a
                        $99/month add-on on every tier, free or paid,
                        so this is a separate provider with its own
                        free rate bucket (60 calls/min)

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
import re
from datetime import date, timedelta, datetime

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
FINNHUB_API_KEY = os.environ.get("FINNHUB_API_KEY")

if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY environment variable is not set. Set it in Render's Environment tab.")
if not APP_PASSWORD_HASH:
    raise RuntimeError("APP_PASSWORD_HASH environment variable is not set. Set it in Render's Environment tab.")
if not MASSIVE_API_KEY:
    raise RuntimeError("MASSIVE_API_KEY environment variable is not set. Set it in Render's Environment tab.")
if not FINNHUB_API_KEY:
    raise RuntimeError("FINNHUB_API_KEY environment variable is not set. Set it in Render's Environment tab.")

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


@app.get("/api/real-regime-check/{etf_ticker}")
def real_regime_check(etf_ticker: str, session: dict = Depends(require_auth)):
    """Real 5-trading-day % price change for a sector or market proxy
    ETF — replaces the mock PROXY_WEEKLY_CHANGE constants from Phase
    3.5. Simpler than the volatility work: no options, no inversion,
    just real aggregates already proven in hv_check."""
    end = date.today()
    start = end - timedelta(days=14)
    url = (f"https://api.massive.com/v2/aggs/ticker/{etf_ticker.upper()}/range/1/day/"
           f"{start.isoformat()}/{end.isoformat()}?adjusted=true&sort=asc&apiKey={MASSIVE_API_KEY}")
    payload = _fetch_json(url)
    results = payload.get("results", [])
    if len(results) < 6:
        raise HTTPException(status_code=502, detail=f"Not enough price history for {etf_ticker.upper()} to compute a 5-day change")

    closes = [bar["c"] for bar in results]
    latest_close = closes[-1]
    five_days_ago_close = closes[-6]
    pct_change = round(((latest_close - five_days_ago_close) / five_days_ago_close) * 100, 2)

    return {"ticker": etf_ticker.upper(), "latestClose": latest_close, "fiveDayChangePct": pct_change}


@app.get("/api/real-technicals-check/{ticker}")
def real_technicals_check(ticker: str, sector_etf: Optional[str] = None, session: dict = Depends(require_auth)):
    """Real Relative Volume, Momentum, Trend/Technical Structure, and
    (if sector_etf is given) Sector Leadership — all from the same
    real price-history endpoint already proven for HV and Regime.
    Sector Leadership compares the stock's own 10-day return against
    its sector proxy ETF's return over the same window — one extra
    real call, only made when a sector ETF is actually provided."""
    end = date.today()
    start = end - timedelta(days=60)
    url = (f"https://api.massive.com/v2/aggs/ticker/{ticker.upper()}/range/1/day/"
           f"{start.isoformat()}/{end.isoformat()}?adjusted=true&sort=asc&apiKey={MASSIVE_API_KEY}")
    payload = _fetch_json(url)
    results = payload.get("results", [])
    if len(results) < 15:
        raise HTTPException(status_code=502, detail=f"Not enough price history for {ticker.upper()} to compute technicals")

    volumes = [bar["v"] for bar in results]
    closes = [bar["c"] for bar in results]

    latest_volume = volumes[-1]
    baseline_volumes = volumes[:-1][-20:]
    avg_volume = sum(baseline_volumes) / len(baseline_volumes)
    rvol = latest_volume / avg_volume if avg_volume > 0 else 1.0

    lookback = min(10, len(closes) - 1)
    ten_day_return_pct = round(((closes[-1] - closes[-1 - lookback]) / closes[-1 - lookback]) * 100, 2)

    rvol_score = max(10, min(95, round(50 + (rvol - 1) * 40)))
    momentum_score = max(10, min(95, round(50 + abs(ten_day_return_pct) * 3)))

    # Trend/Technical Structure — same closes array, no extra API call.
    # A clean trend (short MA well separated from long MA) reads as
    # strong structure regardless of direction; a flat/choppy market
    # reads as weak — same symmetric-magnitude approach as Momentum.
    # Direction itself is Directional Lean's job elsewhere.
    if len(closes) >= 30:
        sma_short = sum(closes[-10:]) / 10
        sma_long = sum(closes[-30:]) / 30
        ma_gap_pct = round((sma_short - sma_long) / sma_long * 100, 2)
        technical_score = max(15, min(95, round(50 + abs(ma_gap_pct) * 10)))
    else:
        ma_gap_pct = 0.0
        technical_score = 50

    # Sector Leadership — only computed if a sector proxy ETF is given.
    # Same 10-trading-day window as Momentum, so the comparison is
    # apples-to-apples: is the stock beating its own sector, or lagging it.
    sector_leadership_score = None
    sector_return_pct = None
    if sector_etf:
        sector_url = (f"https://api.massive.com/v2/aggs/ticker/{sector_etf.upper()}/range/1/day/"
                      f"{start.isoformat()}/{end.isoformat()}?adjusted=true&sort=asc&apiKey={MASSIVE_API_KEY}")
        sector_payload = _fetch_json(sector_url)
        sector_results = sector_payload.get("results", [])
        if len(sector_results) >= lookback + 1:
            sector_closes = [bar["c"] for bar in sector_results]
            sector_return_pct = round(((sector_closes[-1] - sector_closes[-1 - lookback]) / sector_closes[-1 - lookback]) * 100, 2)
            sector_leadership_score = max(10, min(95, round(50 + (ten_day_return_pct - sector_return_pct) * 5)))

    return {
        "ticker": ticker.upper(),
        "latestVolume": latest_volume,
        "averageVolume": round(avg_volume),
        "relativeVolume": round(rvol, 2),
        "relativeVolumeScore": rvol_score,
        "lookbackDays": lookback,
        "priceChangePct": ten_day_return_pct,
        "momentumScore": momentum_score,
        "maGapPct": ma_gap_pct,
        "technicalStructureScore": technical_score,
        "sectorEtf": sector_etf.upper() if sector_etf else None,
        "sectorReturnPct": sector_return_pct,
        "sectorLeadershipScore": sector_leadership_score
    }


BROAD_INDEX_ETFS = {"SPY", "VOO", "IVV", "QQQ", "DIA", "IWM", "VTI", "VT", "VXUS", "MDY"}

# Mirrors the frontend's SECTOR_PROXY mapping — needed server-side too,
# since real_deep_dive has to know which ETF to fetch for Regime when
# the caller doesn't already know the ticker's sector (a brand-new
# scan-discovered ticker, not one of the original ten).
SECTOR_PROXY = {
    "Technology": "XLK", "Semiconductors": "SMH", "Financials": "XLF",
    "Financial Technology": "XLF", "Energy": "XLE", "Energy Services": "XLE",
    "Healthcare": "XLV", "Consumer Staples": "XLP", "Consumer Discretionary": "XLY",
    "Consumer / Auto": "XLY", "Media & Entertainment": "XLC", "Industrials": "XLI"
}

# Keyword match against Massive's SIC description — simpler and more
# robust than memorizing exact SIC code ranges. Falls through to None
# (which the caller treats as "use the broad market proxy") for
# anything genuinely ambiguous, rather than guessing wrong.
SIC_KEYWORD_TO_SECTOR = [
    ("semiconductor", "Semiconductors"),
    ("computer", "Technology"), ("software", "Technology"), ("internet", "Technology"), ("electronic", "Technology"),
    ("bank", "Financials"), ("insurance", "Financials"), ("credit", "Financials"), ("invest", "Financials"), ("financ", "Financials"),
    ("petroleum", "Energy"), ("oil", "Energy"),
    ("drilling", "Energy Services"), ("oilfield", "Energy Services"),
    ("pharmaceutical", "Healthcare"), ("biological", "Healthcare"), ("health", "Healthcare"), ("medical", "Healthcare"), ("hospital", "Healthcare"),
    ("grocery", "Consumer Staples"), ("food", "Consumer Staples"), ("beverage", "Consumer Staples"),
    ("retail", "Consumer Discretionary"), ("apparel", "Consumer Discretionary"), ("department store", "Consumer Discretionary"),
    ("motor vehicle", "Consumer / Auto"), ("automotive", "Consumer / Auto"),
    ("motion picture", "Media & Entertainment"), ("broadcasting", "Media & Entertainment"), ("entertainment", "Media & Entertainment"),
    ("machinery", "Industrials"), ("industrial", "Industrials"), ("aerospace", "Industrials"), ("construction", "Industrials"),
]


def get_sector_for_ticker(ticker):
    """Maps a ticker to one of our known sector buckets via Massive's
    SIC industry classification. Returns None (not a guess) when
    nothing matches — the caller falls back to the broad market proxy
    rather than misclassifying something ambiguous."""
    try:
        payload = _fetch_json(f"https://api.massive.com/v3/reference/tickers/{ticker.upper()}?apiKey={MASSIVE_API_KEY}")
    except HTTPException:
        return None
    raw_results = payload.get("results")
    result = raw_results[0] if isinstance(raw_results, list) and raw_results else (raw_results if isinstance(raw_results, dict) else {})
    sic_desc = (result.get("sic_description") or "").lower()
    for keyword, sector in SIC_KEYWORD_TO_SECTOR:
        if keyword in sic_desc:
            return sector
    return None


_etf_ticker_cache = {"tickers": None, "fetched_at": None}


def get_etf_ticker_set_if_cached():
    """Returns the cached ETF set if warm, or None if it needs
    warming. Deliberately never triggers a fetch itself — that's a
    separate action (see warm_etf_cache) — so real_scan's own call
    budget stays predictable and can't combine with a cold-cache
    fetch to blow through the 5-calls/minute limit in one request."""
    now = datetime.utcnow()
    cached = _etf_ticker_cache["tickers"]
    fetched_at = _etf_ticker_cache["fetched_at"]
    if cached is not None and fetched_at and (now - fetched_at).total_seconds() < 86400:
        return cached
    return None


def warm_etf_cache():
    """Actually fetches and caches the ETF reference set — 3-4 real
    calls. Called explicitly via /api/warm-etf-cache, kept separate
    from real_scan on purpose (see above)."""
    etf_tickers = set()
    url = f"https://api.massive.com/v3/reference/tickers?type=ETF&market=stocks&active=true&limit=1000&apiKey={MASSIVE_API_KEY}"
    pages = 0
    while url and pages < 6:
        payload = _fetch_json(url)
        for r in payload.get("results", []):
            if r.get("ticker"):
                etf_tickers.add(r["ticker"])
        next_url = payload.get("next_url")
        url = f"{next_url}&apiKey={MASSIVE_API_KEY}" if next_url else None
        pages += 1
    _etf_ticker_cache["tickers"] = etf_tickers
    _etf_ticker_cache["fetched_at"] = datetime.utcnow()
    return etf_tickers


@app.post("/api/warm-etf-cache")
def warm_etf_cache_endpoint(session: dict = Depends(require_auth)):
    """Call this once (or once a day) before running a scan. Separate
    from /api/real-scan on purpose — see warm_etf_cache's docstring."""
    tickers = warm_etf_cache()
    return {"warmed": True, "etfCount": len(tickers)}


@app.get("/api/real-deep-dive/{ticker}")
def real_deep_dive(ticker: str, sector_etf: Optional[str] = None, session: dict = Depends(require_auth)):
    """Everything the separate real-data buttons compute, in one
    efficient pass. hv_check and real_technicals_check were each
    independently fetching the same ~60 days of price history for a
    ticker — this fetches it once and reuses it for HV, RVOL,
    Momentum, and Trend. Also drops the redundant underlying-price
    lookup real_iv_check used to make on its own, reusing this same
    fetch's latest close instead. Net result: 5 real calls total (3
    Stocks, 2 Options) instead of 8 — fits inside one minute on both
    rate buckets, which is what makes Stage 2's per-ticker sequencing
    workable without a paid tier. Also makes one call to Finnhub (a
    separate provider and rate bucket) for real Catalyst Strength data.
    Response is shaped to drop directly into the existing
    applyRealVolatility / applyRealTechnicals / applyRealRegime /
    applyRealCatalyst functions client-side — no new frontend mutation
    logic needed, just new plumbing to call them."""
    ticker = ticker.upper()
    end = date.today()
    start = end - timedelta(days=60)
    url = (f"https://api.massive.com/v2/aggs/ticker/{ticker}/range/1/day/"
           f"{start.isoformat()}/{end.isoformat()}?adjusted=true&sort=asc&apiKey={MASSIVE_API_KEY}")
    payload = _fetch_json(url)
    results = payload.get("results", [])
    if len(results) < 15:
        raise HTTPException(status_code=502, detail=f"Not enough price history for {ticker}")

    volumes = [bar["v"] for bar in results]
    closes = [bar["c"] for bar in results]
    price = closes[-1]

    # HV — same formula as hv_check
    log_returns = [math.log(closes[i] / closes[i - 1]) for i in range(1, len(closes))]
    n = len(log_returns)
    mean_return = sum(log_returns) / n
    variance = sum((r - mean_return) ** 2 for r in log_returns) / (n - 1)
    hv_pct = round(math.sqrt(variance) * math.sqrt(252) * 100, 2)

    # RVOL, Momentum, Trend — same formulas as real_technicals_check
    latest_volume = volumes[-1]
    baseline_volumes = volumes[:-1][-20:]
    avg_volume = sum(baseline_volumes) / len(baseline_volumes)
    rvol = latest_volume / avg_volume if avg_volume > 0 else 1.0
    rvol_score = max(10, min(95, round(50 + (rvol - 1) * 40)))

    lookback = min(10, len(closes) - 1)
    ten_day_return_pct = round(((closes[-1] - closes[-1 - lookback]) / closes[-1 - lookback]) * 100, 2)
    momentum_score = max(10, min(95, round(50 + abs(ten_day_return_pct) * 3)))

    if len(closes) >= 30:
        sma_short = sum(closes[-10:]) / 10
        sma_long = sum(closes[-30:]) / 30
        ma_gap_pct = round((sma_short - sma_long) / sma_long * 100, 2)
        technical_score = max(15, min(95, round(50 + abs(ma_gap_pct) * 10)))
    else:
        ma_gap_pct = 0.0
        technical_score = 50

    # IV via Black-Scholes inversion — same as real_iv_check, but reuses
    # `price` above instead of a separate redundant prev-close call
    ref_url = (f"https://api.massive.com/v3/reference/options/contracts"
               f"?underlying_ticker={ticker}&contract_type=call&limit=1000&apiKey={MASSIVE_API_KEY}")
    ref_payload = _fetch_json(ref_url)
    contracts = ref_payload.get("results", [])
    iv_pct = None
    option_contract = None
    today = date.today()
    candidates = []
    for c in contracts:
        parsed = parse_occ_ticker(c["ticker"])
        if not parsed:
            continue
        exp_date = date.fromisoformat(parsed["expiration_date"])
        if 15 <= (exp_date - today).days <= 60:
            candidates.append((exp_date, parsed, c["ticker"]))
    if candidates:
        nearest_exp = min(c[0] for c in candidates)
        same_exp = [c for c in candidates if c[0] == nearest_exp]
        exp_date, parsed, contract_ticker = min(same_exp, key=lambda c: abs(c[1]["strike"] - price))
        opt_payload = _fetch_json(f"https://api.massive.com/v2/aggs/ticker/{contract_ticker}/prev?adjusted=true&apiKey={MASSIVE_API_KEY}")
        opt_results = opt_payload.get("results", [])
        if opt_results:
            option_price = opt_results[0]["c"]
            T = (exp_date - today).days / 365.0
            iv_pct = round(implied_vol_bisection(option_price, price, parsed["strike"], T, RISK_FREE_RATE) * 100, 2)
            option_contract = contract_ticker

    spread = round(iv_pct - hv_pct, 2) if iv_pct is not None else None
    if spread is None:
        vol_bias = "Unknown"
    elif spread > 3:
        vol_bias = "Short Vol"
    elif spread < -3:
        vol_bias = "Long Vol"
    else:
        vol_bias = "Neutral"

    # Regime — sector proxy is auto-detected via SIC classification if
    # the caller doesn't already know the ticker's sector (a brand-new
    # scan-discovered ticker); market proxy (SPY) always runs
    detected_sector = None
    if not sector_etf:
        detected_sector = get_sector_for_ticker(ticker)
        if detected_sector:
            sector_etf = SECTOR_PROXY.get(detected_sector)

    sector_return_pct = None
    sector_leadership_score = None
    if sector_etf:
        sector_payload = _fetch_json(
            f"https://api.massive.com/v2/aggs/ticker/{sector_etf.upper()}/range/1/day/"
            f"{start.isoformat()}/{end.isoformat()}?adjusted=true&sort=asc&apiKey={MASSIVE_API_KEY}")
        sector_results = sector_payload.get("results", [])
        if len(sector_results) >= lookback + 1:
            sector_closes = [bar["c"] for bar in sector_results]
            sector_return_pct = round(((sector_closes[-1] - sector_closes[-1 - lookback]) / sector_closes[-1 - lookback]) * 100, 2)
            sector_leadership_score = max(10, min(95, round(50 + (ten_day_return_pct - sector_return_pct) * 5)))

    market_payload = _fetch_json(
        f"https://api.massive.com/v2/aggs/ticker/SPY/range/1/day/"
        f"{start.isoformat()}/{end.isoformat()}?adjusted=true&sort=asc&apiKey={MASSIVE_API_KEY}")
    market_results = market_payload.get("results", [])
    market_return_pct = None
    if len(market_results) >= 6:
        market_closes = [bar["c"] for bar in market_results]
        market_return_pct = round(((market_closes[-1] - market_closes[-6]) / market_closes[-6]) * 100, 2)

    # Catalyst — separate provider (Finnhub) and rate bucket from
    # everything above, so this doesn't tighten the Massive pacing.
    # Failure here shouldn't sink the whole deep-dive; the caller
    # already handles a None catalyst as "still mock" for this ticker.
    earnings_date = None
    catalyst_hour = None
    days_to_catalyst = None
    try:
        earnings = fetch_next_earnings(ticker)
        if earnings:
            earnings_date = earnings["earningsDate"]
            catalyst_hour = earnings["hour"]
            days_to_catalyst = earnings["daysToCatalyst"]
    except HTTPException:
        pass

    return {
        "ticker": ticker,
        "price": price,
        "historicalVolatilityPct": hv_pct,
        "impliedVolatilityPct": iv_pct,
        "spread": spread,
        "volBias": vol_bias,
        "ivContract": option_contract,
        "relativeVolume": round(rvol, 2),
        "relativeVolumeScore": rvol_score,
        "priceChangePct": ten_day_return_pct,
        "momentumScore": momentum_score,
        "maGapPct": ma_gap_pct,
        "technicalStructureScore": technical_score,
        "sectorEtf": sector_etf.upper() if sector_etf else None,
        "detectedSector": detected_sector,
        "sectorReturnPct": sector_return_pct,
        "sectorLeadershipScore": sector_leadership_score,
        "marketTicker": "SPY",
        "marketReturnPct": market_return_pct,
        "earningsDate": earnings_date,
        "catalystHour": catalyst_hour,
        "daysToCatalyst": days_to_catalyst
    }


@app.get("/api/real-scan")
def real_scan(session: dict = Depends(require_auth)):
    """Stage 1 of Real Scan — a cheap, whole-market screen. Pulls
    Daily Market Summary for the two most recent trading days (2-6
    calls total to find them, walking back over weekends/holidays —
    NOT one call per ticker) and filters locally to a liquid,
    actively-moving shortlist. This does NOT run the full scoring
    engines — that's Stage 2, deliberately kept separate since it
    costs real calls per ticker and can't be run on more than a
    handful at once under the free-tier rate limit."""
    trading_days = []
    d = date.today()
    attempts = 0
    while len(trading_days) < 2 and attempts < 6:
        url = f"https://api.massive.com/v2/aggs/grouped/locale/us/market/stocks/{d.isoformat()}?adjusted=true&apiKey={MASSIVE_API_KEY}"
        try:
            payload = _fetch_json(url)
            results = payload.get("results", [])
            if results:
                trading_days.append((d.isoformat(), results))
        except HTTPException:
            pass
        d -= timedelta(days=1)
        attempts += 1

    if len(trading_days) < 2:
        raise HTTPException(status_code=502, detail="Could not find two recent trading days with data")

    latest_date, latest_results = trading_days[0]
    prior_date, prior_results = trading_days[1]
    prior_by_ticker = {r["T"]: r for r in prior_results if "T" in r}
    ticker_pattern = re.compile(r"^[A-Z]{1,5}$")
    etf_set = get_etf_ticker_set_if_cached()
    etf_filtering_applied = etf_set is not None
    if etf_set is None:
        etf_set = set()  # no filtering this run — every ticker treated as "not an ETF"

    candidates = []
    for r in latest_results:
        ticker = r.get("T", "")
        if not ticker_pattern.match(ticker):
            continue
        if etf_filtering_applied and ticker in etf_set and ticker not in BROAD_INDEX_ETFS:
            continue  # exclude sector/leveraged/bond/commodity ETFs, keep individual stocks and broad market index funds
        close = r.get("c")
        volume = r.get("v")
        if not close or not volume or close < 5:
            continue
        dollar_volume = close * volume
        if dollar_volume < 20_000_000:
            continue
        prior = prior_by_ticker.get(ticker)
        pct_change = round(((close - prior["c"]) / prior["c"]) * 100, 2) if prior and prior.get("c") else None
        candidates.append({
            "ticker": ticker, "close": close, "volume": volume,
            "dollarVolume": round(dollar_volume), "pctChange": pct_change,
            "isEtf": ticker in etf_set
        })

    candidates.sort(key=lambda c: c["dollarVolume"], reverse=True)
    shortlist = candidates[:40]

    return {
        "scanDate": latest_date,
        "comparisonDate": prior_date,
        "totalTickersScanned": len(latest_results),
        "passedLiquidityFilter": len(candidates),
        "etfFilteringApplied": etf_filtering_applied,
        "note": None if etf_filtering_applied else "ETF cache not warm yet — sector/leveraged/bond ETFs weren't filtered this run. Call POST /api/warm-etf-cache, then re-run.",
        "shortlist": shortlist
    }


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


def _fetch_finnhub_json(url):
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        raise HTTPException(status_code=502, detail=f"Finnhub API returned {e.code}: {body}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Could not reach Finnhub API: {str(e)}")


def fetch_next_earnings(ticker):
    """Real next-earnings lookup via Finnhub's free earnings calendar —
    a separate provider and rate bucket (60 calls/min) from Massive, so
    this doesn't compete with the Stocks/Options call budget. Verified
    live before building against it: Massive's own earnings data
    (Benzinga partner feed) is a $99/month add-on on every tier, free
    or paid, so this was the free-tier-first alternative. Returns None
    if nothing is scheduled in the lookup window, rather than guessing."""
    end = date.today() + timedelta(days=365)
    url = (f"https://finnhub.io/api/v1/calendar/earnings?from={date.today().isoformat()}"
           f"&to={end.isoformat()}&symbol={ticker.upper()}&token={FINNHUB_API_KEY}")
    payload = _fetch_finnhub_json(url)
    entries = payload.get("earningsCalendar", [])
    if not entries:
        return None
    upcoming = sorted(entries, key=lambda e: e["date"])[0]
    earnings_date = date.fromisoformat(upcoming["date"])
    return {
        "earningsDate": upcoming["date"],
        "hour": upcoming.get("hour") or None,
        "daysToCatalyst": (earnings_date - date.today()).days
    }


@app.get("/api/real-catalyst-check/{ticker}")
def real_catalyst_check(ticker: str, session: dict = Depends(require_auth)):
    """Real next-earnings date/timing for Catalyst Strength — the
    largest-weighted Opportunity Score driver, previously a random
    placeholder. One call against Finnhub's free tier."""
    result = fetch_next_earnings(ticker.upper())
    if result is None:
        raise HTTPException(status_code=404, detail=f"No upcoming earnings found for {ticker.upper()} in the next year")
    return {"ticker": ticker.upper(), **result}


def parse_occ_ticker(occ_ticker):
    """Parses a standard OCC-format option ticker, e.g. 'O:AAPL260904C00110000'
    -> symbol, expiration date, strike, call/put. Used instead of trusting
    specific reference-endpoint field names, since ticker format is a
    fixed, well-known standard regardless of which endpoint returns it."""
    m = re.match(r"^O:([A-Z]+)(\d{6})([CP])(\d{8})$", occ_ticker)
    if not m:
        return None
    symbol, date_str, cp, strike_str = m.groups()
    yy, mm, dd = date_str[0:2], date_str[2:4], date_str[4:6]
    return {
        "symbol": symbol,
        "expiration_date": f"20{yy}-{mm}-{dd}",
        "strike": int(strike_str) / 1000.0,
        "type": "call" if cp == "C" else "put"
    }


def norm_cdf(x):
    return 0.5 * (1 + math.erf(x / math.sqrt(2)))


def bs_call_price(S, K, T, r, sigma):
    if sigma <= 0 or T <= 0:
        return max(0, S - K)
    d1 = (math.log(S / K) + (r + 0.5 * sigma ** 2) * T) / (sigma * math.sqrt(T))
    d2 = d1 - sigma * math.sqrt(T)
    return S * norm_cdf(d1) - K * math.exp(-r * T) * norm_cdf(d2)


def implied_vol_bisection(market_price, S, K, T, r, tol=1e-6, max_iter=100):
    """Solves for the volatility that makes Black-Scholes agree with a
    real observed market price. Round-trip tested against a known
    synthetic volatility before this ever touched live data."""
    low, high = 0.001, 5.0
    mid = (low + high) / 2
    for _ in range(max_iter):
        mid = (low + high) / 2
        price = bs_call_price(S, K, T, r, mid)
        if abs(price - market_price) < tol:
            return mid
        if price < market_price:
            low = mid
        else:
            high = mid
    return mid


RISK_FREE_RATE = 0.045  # approximate — short-dated ATM IV is not very sensitive to this


@app.get("/api/real-iv-check/{ticker}")
def real_iv_check(ticker: str, session: dict = Depends(require_auth)):
    """Real implied volatility computed by us via Black-Scholes inversion
    on a real, near-term, at-the-money option's actual EOD closing price
    — entirely on Options Basic (free). No snapshot/greeks endpoint
    (which needs Starter, $29/mo) involved anywhere in this path."""
    price_url = f"https://api.massive.com/v2/aggs/ticker/{ticker.upper()}/prev?adjusted=true&apiKey={MASSIVE_API_KEY}"
    price_payload = _fetch_json(price_url)
    stock_results = price_payload.get("results", [])
    if not stock_results:
        raise HTTPException(status_code=502, detail=f"No stock price available for {ticker.upper()}")
    underlying_price = stock_results[0]["c"]

    ref_url = (f"https://api.massive.com/v3/reference/options/contracts"
               f"?underlying_ticker={ticker.upper()}&contract_type=call&limit=1000&apiKey={MASSIVE_API_KEY}")
    ref_payload = _fetch_json(ref_url)
    contracts = ref_payload.get("results", [])
    if not contracts:
        raise HTTPException(status_code=502, detail=f"No option contracts found for {ticker.upper()}")

    today = date.today()
    candidates = []
    for c in contracts:
        parsed = parse_occ_ticker(c["ticker"])
        if not parsed:
            continue
        exp_date = date.fromisoformat(parsed["expiration_date"])
        days_out = (exp_date - today).days
        if 15 <= days_out <= 60:  # avoid 0DTE noise, avoid too-far-out illiquid contracts
            candidates.append((exp_date, parsed, c["ticker"]))

    if not candidates:
        raise HTTPException(status_code=502, detail="No contracts found in the 15-60 day window")

    nearest_exp = min(c[0] for c in candidates)
    same_exp = [c for c in candidates if c[0] == nearest_exp]
    exp_date, parsed, contract_ticker = min(same_exp, key=lambda c: abs(c[1]["strike"] - underlying_price))

    opt_price_url = f"https://api.massive.com/v2/aggs/ticker/{contract_ticker}/prev?adjusted=true&apiKey={MASSIVE_API_KEY}"
    opt_price_payload = _fetch_json(opt_price_url)
    opt_results = opt_price_payload.get("results", [])
    if not opt_results:
        raise HTTPException(status_code=502, detail=f"No price history for contract {contract_ticker}")
    option_market_price = opt_results[0]["c"]

    T = (exp_date - today).days / 365.0
    computed_iv = implied_vol_bisection(option_market_price, underlying_price, parsed["strike"], T, RISK_FREE_RATE)

    return {
        "ticker": ticker.upper(),
        "underlyingPrice": underlying_price,
        "contract": contract_ticker,
        "strike": parsed["strike"],
        "expiration": parsed["expiration_date"],
        "daysToExpiration": (exp_date - today).days,
        "optionMarketPrice": option_market_price,
        "impliedVolatilityPct": round(computed_iv * 100, 2),
        "method": "Black-Scholes inversion on real EOD option price — Options Basic only, no paid tier"
    }


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


@app.get("/api/options-basic-check/{ticker}")
def options_basic_check(ticker: str, session: dict = Depends(require_auth)):
    """Tests whether Options Basic covers reference + historical price
    data (a different category from the snapshot/greeks endpoint,
    which we've confirmed needs Starter). If this works, real IV is
    computable for free via Black-Scholes inversion on real option
    prices — no paid tier needed. If this also 403s, that's the real,
    confirmed boundary of what Basic covers."""
    ref_url = (f"https://api.massive.com/v3/reference/options/contracts"
               f"?underlying_ticker={ticker.upper()}&contract_type=call&limit=10&apiKey={MASSIVE_API_KEY}")
    ref_payload = _fetch_json(ref_url)
    contracts = ref_payload.get("results", [])
    if not contracts:
        return {"referenceDataAccessible": True, "contractsFound": 0,
                "note": "Reference endpoint worked but returned no contracts — try a different ticker."}

    sample_contract = contracts[0]["ticker"]
    price_url = f"https://api.massive.com/v2/aggs/ticker/{sample_contract}/prev?adjusted=true&apiKey={MASSIVE_API_KEY}"
    try:
        price_payload = _fetch_json(price_url)
        return {
            "referenceDataAccessible": True,
            "contractsFound": len(contracts),
            "sampleContract": sample_contract,
            "historicalPriceAccessible": True,
            "samplePriceData": price_payload
        }
    except HTTPException as e:
        return {
            "referenceDataAccessible": True,
            "contractsFound": len(contracts),
            "sampleContract": sample_contract,
            "historicalPriceAccessible": False,
            "error": e.detail
        }
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
    Volatility Bias — both halves pulled from real, free Massive data.
    Uses the Black-Scholes-inverted IV (Options Basic, free), not the
    snapshot endpoint (Starter, $29/mo)."""
    hv_result = hv_check(ticker, session)
    iv_result = real_iv_check(ticker, session)

    hv_pct = hv_result["historicalVolatilityPct"]
    iv_pct = iv_result["impliedVolatilityPct"]
    spread = round(iv_pct - hv_pct, 2)
    if spread > 3:
        bias = "Short Vol"
    elif spread < -3:
        bias = "Long Vol"
    else:
        bias = "Neutral"

    return {
        "ticker": ticker.upper(),
        "price": iv_result["underlyingPrice"],
        "historicalVolatilityPct": hv_pct,
        "impliedVolatilityPct": iv_pct,
        "ivContract": iv_result["contract"],
        "ivMethod": iv_result["method"],
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


@app.post("/api/migrate-add-real-volatility")
def migrate_add_real_volatility(session: dict = Depends(require_auth), db: Session = Depends(get_db)):
    """One-time schema changes — adds real-data columns to the already-
    existing opportunities table. create_all() only creates NEW tables;
    it never alters ones that already exist, so a genuine schema
    change like this needs an explicit step until a real migration
    tool (Alembic) is worth the overhead. Safe to call more than once —
    IF NOT EXISTS makes every statement here a no-op after it's applied."""
    db.execute(text("ALTER TABLE opportunities ADD COLUMN IF NOT EXISTS real_volatility JSON"))
    db.execute(text("ALTER TABLE opportunities ADD COLUMN IF NOT EXISTS real_regime JSON"))
    db.execute(text("ALTER TABLE opportunities ADD COLUMN IF NOT EXISTS real_technicals JSON"))
    db.execute(text("ALTER TABLE opportunities ADD COLUMN IF NOT EXISTS real_catalyst JSON"))
    db.commit()
    return {"migrated": True}


class OpportunityCreate(BaseModel):
    id: str
    sector: str = ""
    status: str = "New"
    opportunityScore: int
    volatilityScore: int
    volBias: str
    ivRank: int = 50
    directionalLean: str = "Neutral"
    suggestedTrade: str = "Pending trade construction"
    thesis: str = ""
    notes: str = ""
    pendingAnalysis: bool = True
    price: Optional[float] = None
    daysToCatalyst: Optional[int] = None
    oppDrivers: Optional[list] = None
    volDrivers: Optional[list] = None
    realVolatility: Optional[dict] = None
    realRegime: Optional[dict] = None
    realTechnicals: Optional[dict] = None
    realCatalyst: Optional[dict] = None


@app.post("/api/opportunities")
def create_opportunity(opp: OpportunityCreate, session: dict = Depends(require_auth), db: Session = Depends(get_db)):
    """Creates a genuinely new opportunity row — the first write
    endpoint that isn't updating something already seeded. Used when
    Real Scan discovers a ticker outside the original mock ten.
    Persists oppDrivers/volDrivers as-computed at creation time — the
    fix for a real persistence gap where a scan-discovered opportunity's
    driver breakdown (Liquidity, the volatility driver set) used to
    regenerate fresh random values on every reload instead of keeping
    what was actually shown. Drivers a real-data fetch can recompute
    (regime, technicals, catalyst) still get correctly overlaid on
    top of this baseline via their own real_* fields — this baseline
    only needs to be right, not to anticipate future real overlays."""
    existing = db.query(models.Opportunity).filter(models.Opportunity.id == opp.id).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"Opportunity {opp.id} already exists")
    new_opp = models.Opportunity(
        id=opp.id, sector=opp.sector, status=opp.status,
        opportunity_score=opp.opportunityScore, volatility_score=opp.volatilityScore,
        vol_bias=opp.volBias, iv_rank=opp.ivRank, directional_lean=opp.directionalLean,
        suggested_trade=opp.suggestedTrade, thesis=opp.thesis, notes=opp.notes,
        pending_analysis=opp.pendingAnalysis, price=opp.price, days_to_catalyst=opp.daysToCatalyst,
        opp_drivers=opp.oppDrivers, vol_drivers=opp.volDrivers,
        real_volatility=opp.realVolatility, real_regime=opp.realRegime, real_technicals=opp.realTechnicals,
        real_catalyst=opp.realCatalyst
    )
    db.add(new_opp)
    db.commit()
    return {"created": True, "id": opp.id}


@app.get("/api/opportunities")
def list_opportunities(session: dict = Depends(require_auth), db: Session = Depends(get_db)):
    opps = db.query(models.Opportunity).all()
    return [
        {
            "id": o.id, "sector": o.sector, "status": o.status,
            "opportunityScore": o.opportunity_score, "volatilityScore": o.volatility_score,
            "volBias": o.vol_bias, "ivRank": o.iv_rank, "directionalLean": o.directional_lean,
            "suggestedTrade": o.suggested_trade, "thesis": o.thesis, "notes": o.notes,
            "pendingAnalysis": o.pending_analysis, "price": o.price, "daysToCatalyst": o.days_to_catalyst,
            "oppDrivers": o.opp_drivers, "volDrivers": o.vol_drivers,
            "realVolatility": o.real_volatility, "realRegime": o.real_regime, "realTechnicals": o.real_technicals,
            "realCatalyst": o.real_catalyst,
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
    price: Optional[float] = None
    volBias: Optional[str] = None
    daysToCatalyst: Optional[int] = None
    oppDrivers: Optional[list] = None
    volDrivers: Optional[list] = None
    realVolatility: Optional[dict] = None
    realRegime: Optional[dict] = None
    realTechnicals: Optional[dict] = None
    realCatalyst: Optional[dict] = None


@app.patch("/api/opportunities/{opp_id}")
def update_opportunity(opp_id: str, update: OpportunityUpdate,
                        session: dict = Depends(require_auth), db: Session = Depends(get_db)):
    """Persists status, notes, real price/volatility/regime/catalyst
    data pulled from Massive and Finnhub, and the current driver
    breakdown (oppDrivers/volDrivers) — the latter kept in sync here so
    a scan-discovered opportunity's stored baseline reflects whatever
    real overlays have landed since creation, not just its creation-
    time snapshot. Trade construction/quality/conviction are still
    derived fresh client-side from this data each load, not stored
    themselves — they're pure functions of it, so storing them too
    would just be redundant duplicated state."""
    opp = db.query(models.Opportunity).filter(models.Opportunity.id == opp_id).first()
    if not opp:
        raise HTTPException(status_code=404, detail=f"No opportunity with id {opp_id}")
    if update.status is not None:
        opp.status = update.status
    if update.notes is not None:
        opp.notes = update.notes
    if update.price is not None:
        opp.price = update.price
    if update.volBias is not None:
        opp.vol_bias = update.volBias
    if update.daysToCatalyst is not None:
        opp.days_to_catalyst = update.daysToCatalyst
    if update.oppDrivers is not None:
        opp.opp_drivers = update.oppDrivers
    if update.volDrivers is not None:
        opp.vol_drivers = update.volDrivers
    if update.realVolatility is not None:
        opp.real_volatility = update.realVolatility
    if update.realRegime is not None:
        opp.real_regime = update.realRegime
    if update.realTechnicals is not None:
        opp.real_technicals = update.realTechnicals
    if update.realCatalyst is not None:
        opp.real_catalyst = update.realCatalyst
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
