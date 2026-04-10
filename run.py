"""KronoTrace — Server Entry Point"""
import uvicorn

if __name__ == "__main__":
    print("\n" + "="*60)
    print("  KronoTrace v3.0 — Forensic Log Analysis Platform")
    print("  Dashboard: http://localhost:8000")
    print("="*60 + "\n")
    uvicorn.run("api:app", host="0.0.0.0", port=8000)
