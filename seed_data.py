"""
OIP Backend — seed data (Step 3, checkpoint 3).

Core fields only for opportunities — enough to browse, identify, and
prove persistence genuinely works. The full nested engine output
(driver breakdowns, trade construction cards, Trade Quality/Conviction
detail) isn't hand-transcribed here; that gets populated for real once
the frontend is rewired to push its own computed output through real
write endpoints (next checkpoint). Hand-copying that much nested JSON
here would be slow and error-prone for something the frontend will
supply correctly on its own very soon.

Journal entries are seeded with full fidelity — they're flat enough
that transcribing them accurately is straightforward and low-risk.

Every number below matches what this session's actual engine runs
produced earlier — not reinvented, copied from real test output.
"""

SEED_OPPORTUNITIES = [
    {"id": "AAPL", "sector": "Technology", "status": "New", "opportunity_score": 81, "volatility_score": 74,
     "vol_bias": "Long Vol", "iv_rank": 28, "directional_lean": "Bullish", "suggested_trade": "Long Call",
     "thesis": "Options are pricing a smaller post-earnings move than recent quarters have actually delivered.",
     "notes": "", "pending_analysis": False},
    {"id": "MSFT", "sector": "Technology", "status": "New", "opportunity_score": 65, "volatility_score": 43,
     "vol_bias": "Neutral", "iv_rank": 50, "directional_lean": "Neutral", "suggested_trade": "No structure — monitor only",
     "thesis": "Strong setup, but current options pricing looks fair — no clean volatility edge to act on yet.",
     "notes": "", "pending_analysis": False},
    {"id": "TSLA", "sector": "Consumer / Auto", "status": "Watchlist", "opportunity_score": 81, "volatility_score": 80,
     "vol_bias": "Long Vol", "iv_rank": 30, "directional_lean": "Neutral", "suggested_trade": "Straddle",
     "thesis": "Delivery-number uncertainty into the print, with a term structure that hasn't caught up to how violently this name has historically moved on surprises.",
     "notes": "Watching for confirmation on delivery estimates before moving to Trade Candidate.", "pending_analysis": False},
    {"id": "JPM", "sector": "Financials", "status": "Trade Candidate", "opportunity_score": 66, "volatility_score": 60,
     "vol_bias": "Short Vol", "iv_rank": 72, "directional_lean": "Bullish", "suggested_trade": "Put Credit Spread",
     "thesis": "IV bid up ahead of the sector's earnings cluster more than this name's own historical reaction justifies.",
     "notes": "", "pending_analysis": False},
    {"id": "XOM", "sector": "Energy", "status": "New", "opportunity_score": 56, "volatility_score": 60,
     "vol_bias": "Long Vol", "iv_rank": 33, "directional_lean": "Bullish", "suggested_trade": "Long Call",
     "thesis": "Crude has been chopping in a wide range; options pricing hasn't adjusted to the recent pickup in realized movement.",
     "notes": "", "pending_analysis": False},
    {"id": "UNH", "sector": "Healthcare", "status": "Open Position", "opportunity_score": 76, "volatility_score": 75,
     "vol_bias": "Long Vol", "iv_rank": 30, "directional_lean": "Bullish", "suggested_trade": "Long Call",
     "thesis": "Regulatory-headline sensitivity combined with an underpriced expected move ahead of guidance commentary.",
     "notes": "Entered on confirmation of technical breakout above prior resistance.", "pending_analysis": False},
    {"id": "COST", "sector": "Consumer Staples", "status": "Analyzed", "opportunity_score": 50, "volatility_score": 36,
     "vol_bias": "Neutral", "iv_rank": 48, "directional_lean": "Neutral", "suggested_trade": "No structure — monitor only",
     "thesis": "Solid business, no live catalyst, volatility pricing looks appropriately calm.",
     "notes": "", "pending_analysis": False},
    {"id": "AMD", "sector": "Semiconductors", "status": "New", "opportunity_score": 84, "volatility_score": 82,
     "vol_bias": "Long Vol", "iv_rank": 32, "directional_lean": "Bullish", "suggested_trade": "Long Call",
     "thesis": "Sector-wide momentum plus a specific term-structure kink around the upcoming print — the cleanest alignment in the queue.",
     "notes": "", "pending_analysis": False},
    {"id": "DIS", "sector": "Media & Entertainment", "status": "Reject", "opportunity_score": 47, "volatility_score": 47,
     "vol_bias": "Neutral", "iv_rank": 52, "directional_lean": "Neutral", "suggested_trade": "No structure — rejected",
     "thesis": "Initial scan flagged elevated relative volume, but no clean catalyst or mispricing on deeper review.",
     "notes": "", "pending_analysis": False},
    {"id": "SLB", "sector": "Energy Services", "status": "Watchlist", "opportunity_score": 52, "volatility_score": 59,
     "vol_bias": "Short Vol", "iv_rank": 70, "directional_lean": "Bullish", "suggested_trade": "Put Credit Spread",
     "thesis": "Options carrying a volatility premium left over from a prior guidance scare the business has since stabilized past.",
     "notes": "", "pending_analysis": False},
]

SEED_JOURNAL_ENTRIES = [
    {"id": "J-seed-1", "opp_id": "AAPL", "ticker": "AAPL", "sector": "Technology", "logged_date": "Jul 2, 2026", "status_at_log": "Closed", "opportunity_score": 78, "volatility_score": 72, "trade_quality_composite": 66, "conviction_composite": 74, "structure": "Call Debit Spread", "thesis": "", "rationale": "IV underpricing pre-earnings move.", "outcome": "Win", "realized_pnl": "+310", "lessons_learned": "Entered with enough runway before the print.", "regime_at_log": "Normal", "days_to_catalyst_at_log": 4},
    {"id": "J-seed-2", "opp_id": "NVDA", "ticker": "NVDA", "sector": "Semiconductors", "logged_date": "Jul 5, 2026", "status_at_log": "Closed", "opportunity_score": 85, "volatility_score": 79, "trade_quality_composite": 68, "conviction_composite": 77, "structure": "Call Debit Spread", "thesis": "", "rationale": "Sector leadership plus underpriced move.", "outcome": "Win", "realized_pnl": "+265", "lessons_learned": "", "regime_at_log": "Normal", "days_to_catalyst_at_log": 6},
    {"id": "J-seed-3", "opp_id": "TSLA", "ticker": "TSLA", "sector": "Consumer / Auto", "logged_date": "Jul 9, 2026", "status_at_log": "Closed", "opportunity_score": 81, "volatility_score": 80, "trade_quality_composite": 53, "conviction_composite": 58, "structure": "Straddle", "thesis": "", "rationale": "Delivery-number uncertainty, no clean direction.", "outcome": "Loss", "realized_pnl": "-180", "lessons_learned": "Premium was too rich relative to the typical move.", "regime_at_log": "Normal", "days_to_catalyst_at_log": 3},
    {"id": "J-seed-4", "opp_id": "JPM", "ticker": "JPM", "sector": "Financials", "logged_date": "Jul 11, 2026", "status_at_log": "Closed", "opportunity_score": 66, "volatility_score": 60, "trade_quality_composite": 58, "conviction_composite": 64, "structure": "Put Credit Spread", "thesis": "", "rationale": "Sector IV overpriced relative to this name's history.", "outcome": "Win", "realized_pnl": "+140", "lessons_learned": "", "regime_at_log": "Normal", "days_to_catalyst_at_log": 6},
    {"id": "J-seed-5", "opp_id": "XOM", "ticker": "XOM", "sector": "Energy", "logged_date": "Jul 14, 2026", "status_at_log": "Closed", "opportunity_score": 60, "volatility_score": 60, "trade_quality_composite": 61, "conviction_composite": 62, "structure": "Call Debit Spread", "thesis": "", "rationale": "ATR pickup underpriced by term structure.", "outcome": "Win", "realized_pnl": "+220", "lessons_learned": "", "regime_at_log": "Normal", "days_to_catalyst_at_log": 15},
    {"id": "J-seed-6", "opp_id": "AMD", "ticker": "AMD", "sector": "Semiconductors", "logged_date": "Jul 18, 2026", "status_at_log": "Closed", "opportunity_score": 88, "volatility_score": 83, "trade_quality_composite": 63, "conviction_composite": 73, "structure": "Long Call", "thesis": "", "rationale": "Cleanest alignment across every driver this cycle.", "outcome": "Win", "realized_pnl": "+480", "lessons_learned": "High-conviction setups are worth sizing up on.", "regime_at_log": "Normal", "days_to_catalyst_at_log": 5},
    {"id": "J-seed-7", "opp_id": "SLB", "ticker": "SLB", "sector": "Energy Services", "logged_date": "Jul 20, 2026", "status_at_log": "Closed", "opportunity_score": 52, "volatility_score": 59, "trade_quality_composite": 49, "conviction_composite": 59, "structure": "Put Credit Spread", "thesis": "", "rationale": "Residual premium from an old guidance scare.", "outcome": "Win", "realized_pnl": "+95", "lessons_learned": "", "regime_at_log": "Normal", "days_to_catalyst_at_log": 9},
    {"id": "J-seed-8", "opp_id": "DIS", "ticker": "DIS", "sector": "Media & Entertainment", "logged_date": "Jul 21, 2026", "status_at_log": "Reject", "opportunity_score": 45, "volatility_score": 52, "trade_quality_composite": None, "conviction_composite": None, "structure": "No structure — rejected", "thesis": "", "rationale": "Volume spike traced to sector rotation, not a real catalyst.", "outcome": "Good call", "realized_pnl": "", "lessons_learned": "Glad this got filtered out before wasting a slot.", "regime_at_log": "Elevated", "days_to_catalyst_at_log": 25},
    {"id": "J-seed-9", "opp_id": "MU", "ticker": "MU", "sector": "Semiconductors", "logged_date": "Jul 24, 2026", "status_at_log": "Closed", "opportunity_score": 70, "volatility_score": 75, "trade_quality_composite": 51, "conviction_composite": 55, "structure": "Straddle", "thesis": "", "rationale": "Sector volatile into print, no directional edge.", "outcome": "Loss", "realized_pnl": "-310", "lessons_learned": "Elevated regime should have been a bigger red flag.", "regime_at_log": "Elevated", "days_to_catalyst_at_log": 4},
    {"id": "J-seed-10", "opp_id": "BA", "ticker": "BA", "sector": "Industrials", "logged_date": "Jul 27, 2026", "status_at_log": "Closed", "opportunity_score": 58, "volatility_score": 55, "trade_quality_composite": 56, "conviction_composite": 60, "structure": "Iron Condor", "thesis": "", "rationale": "IV rich relative to realized, no directional catalyst.", "outcome": "Win", "realized_pnl": "+85", "lessons_learned": "", "regime_at_log": "Normal", "days_to_catalyst_at_log": 18},
    {"id": "J-seed-11", "opp_id": "GOOGL", "ticker": "GOOGL", "sector": "Technology", "logged_date": "Jul 29, 2026", "status_at_log": "Closed", "opportunity_score": 74, "volatility_score": 68, "trade_quality_composite": 62, "conviction_composite": 69, "structure": "Call Debit Spread", "thesis": "", "rationale": "Underpriced move into ad-revenue guidance.", "outcome": "Win", "realized_pnl": "+190", "lessons_learned": "", "regime_at_log": "Normal", "days_to_catalyst_at_log": 7},
    {"id": "J-seed-12", "opp_id": "NFLX", "ticker": "NFLX", "sector": "Media & Entertainment", "logged_date": "Aug 1, 2026", "status_at_log": "Closed", "opportunity_score": 55, "volatility_score": 58, "trade_quality_composite": 45, "conviction_composite": 48, "structure": "Long Put", "thesis": "", "rationale": "Subscriber growth concern into print.", "outcome": "Loss", "realized_pnl": "-150", "lessons_learned": "Low conviction going in — should have passed.", "regime_at_log": "Watch", "days_to_catalyst_at_log": 12},
    {"id": "J-seed-13", "opp_id": "WMT", "ticker": "WMT", "sector": "Consumer Staples", "logged_date": "Aug 3, 2026", "status_at_log": "Closed", "opportunity_score": 57, "volatility_score": 54, "trade_quality_composite": 59, "conviction_composite": 64, "structure": "Put Credit Spread", "thesis": "", "rationale": "IV rich vs. this name's typically calm reaction.", "outcome": "Win", "realized_pnl": "+110", "lessons_learned": "", "regime_at_log": "Normal", "days_to_catalyst_at_log": 20},
    {"id": "J-seed-14", "opp_id": "CAT", "ticker": "CAT", "sector": "Industrials", "logged_date": "Aug 5, 2026", "status_at_log": "Closed", "opportunity_score": 54, "volatility_score": 52, "trade_quality_composite": 55, "conviction_composite": 58, "structure": "Call Credit Spread", "thesis": "", "rationale": "Sector IV rich, bearish drift expected.", "outcome": "Win", "realized_pnl": "+75", "lessons_learned": "", "regime_at_log": "Normal", "days_to_catalyst_at_log": 14},
    {"id": "J-seed-15", "opp_id": "UNH", "ticker": "UNH", "sector": "Healthcare", "logged_date": "Aug 8, 2026", "status_at_log": "Closed", "opportunity_score": 74, "volatility_score": 80, "trade_quality_composite": 62, "conviction_composite": 68, "structure": "Call Debit Spread", "thesis": "", "rationale": "Underpriced move into policy commentary.", "outcome": "Win", "realized_pnl": "+420", "lessons_learned": "", "regime_at_log": "Normal", "days_to_catalyst_at_log": 6},
    {"id": "J-seed-16", "opp_id": "PYPL", "ticker": "PYPL", "sector": "Financial Technology", "logged_date": "Aug 10, 2026", "status_at_log": "Closed", "opportunity_score": 62, "volatility_score": 65, "trade_quality_composite": 50, "conviction_composite": 52, "structure": "Straddle", "thesis": "", "rationale": "Uncertain direction into guidance.", "outcome": "Loss", "realized_pnl": "-220", "lessons_learned": "Another straddle loss during an elevated-regime stretch.", "regime_at_log": "Elevated", "days_to_catalyst_at_log": 5},
    {"id": "J-seed-17", "opp_id": "LULU", "ticker": "LULU", "sector": "Consumer Discretionary", "logged_date": "Aug 13, 2026", "status_at_log": "Closed", "opportunity_score": 68, "volatility_score": 63, "trade_quality_composite": 60, "conviction_composite": 70, "structure": "Call Debit Spread", "thesis": "", "rationale": "Technical breakout plus underpriced move.", "outcome": "Win", "realized_pnl": "+160", "lessons_learned": "", "regime_at_log": "Normal", "days_to_catalyst_at_log": 8},
    {"id": "J-seed-18", "opp_id": "MRK", "ticker": "MRK", "sector": "Healthcare", "logged_date": "Aug 15, 2026", "status_at_log": "Closed", "opportunity_score": 59, "volatility_score": 57, "trade_quality_composite": 58, "conviction_composite": 67, "structure": "Put Credit Spread", "thesis": "", "rationale": "Calm historical reaction, IV overpriced.", "outcome": "Win", "realized_pnl": "+130", "lessons_learned": "", "regime_at_log": "Normal", "days_to_catalyst_at_log": 11},
    {"id": "J-seed-19", "opp_id": "F", "ticker": "F", "sector": "Consumer / Auto", "logged_date": "Aug 17, 2026", "status_at_log": "Closed", "opportunity_score": 51, "volatility_score": 54, "trade_quality_composite": 47, "conviction_composite": 51, "structure": "Long Call", "thesis": "", "rationale": "Marginal setup, took it anyway.", "outcome": "Loss", "realized_pnl": "-190", "lessons_learned": "Conviction was under 55 — this is becoming a pattern worth respecting.", "regime_at_log": "Watch", "days_to_catalyst_at_log": 9},
    {"id": "J-seed-20", "opp_id": "DE", "ticker": "DE", "sector": "Industrials", "logged_date": "Aug 19, 2026", "status_at_log": "Closed", "opportunity_score": 65, "volatility_score": 61, "trade_quality_composite": 63, "conviction_composite": 72, "structure": "Call Debit Spread", "thesis": "", "rationale": "Strong technical structure into equipment demand data.", "outcome": "Win", "realized_pnl": "+175", "lessons_learned": "", "regime_at_log": "Normal", "days_to_catalyst_at_log": 10},
    {"id": "J-seed-21", "opp_id": "COST", "ticker": "COST", "sector": "Consumer Staples", "logged_date": "Aug 21, 2026", "status_at_log": "Reject", "opportunity_score": 50, "volatility_score": 36, "trade_quality_composite": None, "conviction_composite": None, "structure": "No structure — rejected", "thesis": "", "rationale": "No catalyst, no mispricing — nothing to act on.", "outcome": "Passed", "realized_pnl": "", "lessons_learned": "", "regime_at_log": "Normal", "days_to_catalyst_at_log": 20},
    {"id": "J-seed-22", "opp_id": "XOM", "ticker": "XOM", "sector": "Energy", "logged_date": "Aug 24, 2026", "status_at_log": "Closed", "opportunity_score": 56, "volatility_score": 66, "trade_quality_composite": 20, "conviction_composite": 50, "structure": "Straddle", "thesis": "", "rationale": "Energy sector-wide volatility, no directional read.", "outcome": "Loss", "realized_pnl": "-260", "lessons_learned": "Straddles keep underperforming for me.", "regime_at_log": "Elevated", "days_to_catalyst_at_log": 15},
]
