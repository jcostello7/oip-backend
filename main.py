"""
OIP Backend — Step 1: Skeleton

Purpose of this file, right now, is deliberately narrow: prove that
GitHub -> Render -> a live URL actually works, before anything real
(auth, database, Polygon) gets added on top of it. One endpoint,
nothing else.
"""

from fastapi import FastAPI

app = FastAPI(title="OIP Backend")


@app.get("/health")
def health():
    return {"status": "ok", "service": "oip-backend", "step": 1}


@app.get("/")
def root():
    return {"message": "OIP backend is running. Try /health next."}
