"""
OIP Backend — database models (Step 3, checkpoint 2).

Mirrors the JS objects the frontend already trusts (the mock
opportunities, the mock journal entries) as closely as possible.
Complex nested engine output — driver breakdowns, trade construction,
trade quality, conviction — is stored as JSON columns rather than
fully normalized into a dozen tables. Faster to build, still queryable
later if it's ever needed.
"""

from sqlalchemy import Column, String, Integer, Float, Boolean, Text, JSON
from database import Base


class Opportunity(Base):
    __tablename__ = "opportunities"

    id = Column(String, primary_key=True)  # ticker, e.g. "AAPL"
    sector = Column(String)
    status = Column(String, default="New")
    date_added = Column(String)
    last_updated = Column(String)
    pending_analysis = Column(Boolean, default=False)

    opportunity_score = Column(Integer)
    opp_drivers = Column(JSON)  # [[name, value], ...]

    volatility_score = Column(Integer)
    iv_rank = Column(Integer)
    vol_bias = Column(String)
    vol_drivers = Column(JSON)

    regime = Column(JSON)  # sector/market proxy context
    directional_lean = Column(String)
    real_volatility = Column(JSON, nullable=True)  # {historicalVolatilityPct, impliedVolatilityPct, spread, fetchedAt}

    price = Column(Float)
    historical_move_pct = Column(Float)
    implied_move_pct = Column(Float)
    days_to_catalyst = Column(Integer)

    suggested_trade = Column(String)
    trade_construction = Column(JSON)  # {recommended, alternatives}
    trade_quality = Column(JSON)       # {chain, instance, quality}
    conviction = Column(JSON)          # {scores, notes, composite}

    thesis = Column(Text)
    thinking = Column(Text)
    risk_factors = Column(Text)
    notes = Column(Text)

    position = Column(JSON, nullable=True)    # Open Position entry/exit tracking
    rejection = Column(JSON, nullable=True)   # {reason, date} when rejected
    journal_entry_id = Column(String, nullable=True)


class JournalEntry(Base):
    __tablename__ = "journal_entries"

    id = Column(String, primary_key=True)
    opp_id = Column(String)
    ticker = Column(String)
    sector = Column(String)
    logged_date = Column(String)
    status_at_log = Column(String)

    opportunity_score = Column(Integer)
    volatility_score = Column(Integer)
    trade_quality_composite = Column(Integer, nullable=True)
    conviction_composite = Column(Integer, nullable=True)

    structure = Column(String)
    thesis = Column(Text)
    rationale = Column(Text)

    outcome = Column(String)
    realized_pnl = Column(String)
    lessons_learned = Column(Text)

    regime_at_log = Column(String, nullable=True)
    days_to_catalyst_at_log = Column(Integer, nullable=True)
