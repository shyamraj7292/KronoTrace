"""
KronoTrace — FastAPI Application
Handles file uploads, orchestrates the ingestion/detection pipeline,
and streams results to the frontend via WebSocket.
"""

import asyncio
import json
import os
import uuid
import shutil
import tempfile
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any

from fastapi import FastAPI, UploadFile, File, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware

from ingestion.parsers import parse_file, get_supported_extensions, SUPPORTED_EXTENSIONS
from ingestion.normalizer import normalize_records, merge_and_sort, EventLog
from detection.engine import EventCorrelationModule

# ─── App Setup ────────────────────────────────────────────────────────────────

app = FastAPI(
    title="KronoTrace",
    description="Forensic Log Analysis & Threat Detection Platform",
    version="3.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

pipelines: Dict[str, Dict] = {}
ws_connections: Dict[str, List[WebSocket]] = {}

UPLOAD_DIR = Path(tempfile.gettempdir()) / "kronotrace_uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

STATIC_DIR = Path(__file__).parent / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", response_class=HTMLResponse)
async def index():
    index_path = STATIC_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    return HTMLResponse("<h1>KronoTrace - Static files not found</h1>")


@app.get("/api/info")
async def api_info():
    return {
        "name": "KronoTrace",
        "version": "3.0.0",
        "supported_extensions": get_supported_extensions(),
        "detectors": [
            "brute_force", "new_ip", "privilege_escalation",
            "file_access_anomaly", "data_exfiltration"
        ],
    }


@app.post("/api/upload")
async def upload_files(files: List[UploadFile] = File(...)):
    if not files:
        raise HTTPException(status_code=400, detail="No files provided")

    pipeline_id = str(uuid.uuid4())
    pipeline_dir = UPLOAD_DIR / pipeline_id
    pipeline_dir.mkdir(parents=True, exist_ok=True)

    saved_files = []
    rejected_files = []

    for f in files:
        ext = Path(f.filename).suffix.lower()
        if ext not in SUPPORTED_EXTENSIONS:
            rejected_files.append({"filename": f.filename, "reason": f"Unsupported file type: {ext}"})
            continue
        filepath = pipeline_dir / f.filename
        try:
            content = await f.read()
            with open(filepath, 'wb') as out:
                out.write(content)
            saved_files.append({
                "filename": f.filename, "size": len(content),
                "type": ext, "path": str(filepath),
            })
        except Exception as e:
            rejected_files.append({"filename": f.filename, "reason": str(e)})

    if not saved_files:
        raise HTTPException(status_code=400, detail=f"No valid files. Rejected: {rejected_files}")

    pipelines[pipeline_id] = {
        "id": pipeline_id, "status": "queued", "files": saved_files,
        "rejected_files": rejected_files,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "events": [], "alerts": [], "summary": {},
    }

    asyncio.create_task(_run_pipeline(pipeline_id))

    return {
        "pipeline_id": pipeline_id, "status": "queued",
        "accepted_files": len(saved_files), "rejected_files": rejected_files,
        "message": f"Connect to WebSocket at /ws/{pipeline_id} for live updates.",
    }


@app.get("/api/status/{pipeline_id}")
async def get_pipeline_status(pipeline_id: str):
    if pipeline_id not in pipelines:
        raise HTTPException(status_code=404, detail="Pipeline not found")
    p = pipelines[pipeline_id]
    return {
        "id": pipeline_id, "status": p["status"],
        "total_events": len(p.get("events", [])),
        "total_alerts": len(p.get("alerts", [])),
        "summary": p.get("summary", {}),
    }


@app.get("/api/results/{pipeline_id}")
async def get_pipeline_results(pipeline_id: str):
    if pipeline_id not in pipelines:
        raise HTTPException(status_code=404, detail="Pipeline not found")
    p = pipelines[pipeline_id]
    return {
        "id": pipeline_id, "status": p["status"],
        "events": [e.to_dict() for e in p.get("events", [])],
        "alerts": [a.to_dict() if hasattr(a, 'to_dict') else a for a in p.get("alerts", [])],
        "summary": p.get("summary", {}),
    }


# ─── WebSocket ────────────────────────────────────────────────────────────────

@app.websocket("/ws/{pipeline_id}")
async def websocket_endpoint(websocket: WebSocket, pipeline_id: str):
    await websocket.accept()
    if pipeline_id not in ws_connections:
        ws_connections[pipeline_id] = []
    ws_connections[pipeline_id].append(websocket)

    try:
        if pipeline_id in pipelines and pipelines[pipeline_id]["status"] == "complete":
            await _send_cached_results(websocket, pipelines[pipeline_id])

        while True:
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=300)
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "ping"})
            except WebSocketDisconnect:
                break
    except Exception:
        pass
    finally:
        if pipeline_id in ws_connections:
            ws_connections[pipeline_id] = [ws for ws in ws_connections[pipeline_id] if ws != websocket]


async def _broadcast(pipeline_id: str, message: dict):
    if pipeline_id not in ws_connections:
        return
    dead = []
    for ws in ws_connections[pipeline_id]:
        try:
            await ws.send_json(message)
        except Exception:
            dead.append(ws)
    for ws in dead:
        ws_connections[pipeline_id].remove(ws)


async def _send_cached_results(websocket: WebSocket, pipeline: dict):
    events = pipeline.get("events", [])
    if events:
        batch_size = 100
        for i in range(0, len(events), batch_size):
            batch = events[i:i + batch_size]
            await websocket.send_json({
                "type": "events",
                "batch": [e.to_dict() if hasattr(e, 'to_dict') else e for e in batch],
                "batch_number": i // batch_size + 1,
                "total_batches": (len(events) + batch_size - 1) // batch_size,
            })
    alerts = pipeline.get("alerts", [])
    if alerts:
        await websocket.send_json({
            "type": "alerts",
            "data": [a.to_dict() if hasattr(a, 'to_dict') else a for a in alerts],
        })
    summary = pipeline.get("summary", {})
    if summary:
        await websocket.send_json({"type": "summary", "data": summary})
    await websocket.send_json({"type": "complete"})


# ─── Pipeline Processing ─────────────────────────────────────────────────────

async def _run_pipeline(pipeline_id: str):
    pipeline = pipelines[pipeline_id]
    pipeline["status"] = "running"

    try:
        all_raw_records = []
        total_files = len(pipeline["files"])

        # Stage 1: Parsing
        await _broadcast(pipeline_id, {
            "type": "progress", "stage": "parsing", "percent": 0,
            "detail": f"Starting to parse {total_files} file(s)...",
        })

        for file_idx, file_info in enumerate(pipeline["files"]):
            filename = file_info["filename"]
            filepath = file_info["path"]

            await _broadcast(pipeline_id, {
                "type": "progress", "stage": "parsing",
                "percent": int((file_idx / total_files) * 30),
                "detail": f"Parsing {filename} ({file_info['type']})...",
                "current_file": filename,
                "file_number": file_idx + 1, "total_files": total_files,
            })

            loop = asyncio.get_event_loop()
            try:
                records = await loop.run_in_executor(None, parse_file, filepath)
                all_raw_records.extend(records)
                await _broadcast(pipeline_id, {
                    "type": "progress", "stage": "parsing",
                    "percent": int(((file_idx + 1) / total_files) * 30),
                    "detail": f"Parsed {filename}: {len(records)} records extracted",
                    "records_found": len(records),
                })
            except Exception as e:
                await _broadcast(pipeline_id, {
                    "type": "progress", "stage": "parsing",
                    "detail": f"Error parsing {filename}: {str(e)}", "error": True,
                })
                traceback.print_exc()

            await asyncio.sleep(0.1)

        if not all_raw_records:
            await _broadcast(pipeline_id, {
                "type": "error", "message": "No records could be parsed from uploaded files.",
            })
            pipeline["status"] = "error"
            return

        # Stage 2: Normalization
        await _broadcast(pipeline_id, {
            "type": "progress", "stage": "normalization", "percent": 35,
            "detail": f"Normalizing {len(all_raw_records)} records...",
        })

        loop = asyncio.get_event_loop()
        normalized = await loop.run_in_executor(None, normalize_records, all_raw_records)

        await _broadcast(pipeline_id, {
            "type": "progress", "stage": "normalization", "percent": 50,
            "detail": f"Normalized {len(normalized)} events to unified schema",
        })
        await asyncio.sleep(0.1)

        # Stage 3: Processing
        await _broadcast(pipeline_id, {
            "type": "progress", "stage": "processing", "percent": 55,
            "detail": "Merging and sorting events chronologically...",
        })

        sorted_events = await loop.run_in_executor(None, merge_and_sort, normalized)

        await _broadcast(pipeline_id, {
            "type": "progress", "stage": "processing", "percent": 60,
            "detail": f"Sorted {len(sorted_events)} events into timeline",
        })
        await asyncio.sleep(0.1)

        # Stage 4: Detection
        await _broadcast(pipeline_id, {
            "type": "progress", "stage": "detection", "percent": 65,
            "detail": "Running detection algorithms...",
        })

        detector = EventCorrelationModule()
        annotated_events, alerts, summary = await loop.run_in_executor(
            None, detector.analyze, sorted_events
        )

        await _broadcast(pipeline_id, {
            "type": "progress", "stage": "detection", "percent": 80,
            "detail": f"Detection complete: {len(alerts)} threat(s) identified",
        })
        await asyncio.sleep(0.1)

        # Stage 5: Stream results
        await _broadcast(pipeline_id, {
            "type": "progress", "stage": "streaming", "percent": 85,
            "detail": "Streaming results to dashboard...",
        })

        batch_size = 100
        total_batches = (len(annotated_events) + batch_size - 1) // batch_size

        for batch_num in range(total_batches):
            start = batch_num * batch_size
            end = min(start + batch_size, len(annotated_events))
            batch = annotated_events[start:end]

            await _broadcast(pipeline_id, {
                "type": "events",
                "batch": [e.to_dict() for e in batch],
                "batch_number": batch_num + 1,
                "total_batches": total_batches,
            })

            progress = 85 + int((batch_num / total_batches) * 10)
            await _broadcast(pipeline_id, {
                "type": "progress", "stage": "streaming", "percent": progress,
                "detail": f"Streamed batch {batch_num + 1}/{total_batches}",
            })
            await asyncio.sleep(0.05)

        if alerts:
            await _broadcast(pipeline_id, {
                "type": "alerts", "data": [a.to_dict() for a in alerts],
            })

        await _broadcast(pipeline_id, {"type": "summary", "data": summary})

        pipeline["events"] = annotated_events
        pipeline["alerts"] = alerts
        pipeline["summary"] = summary
        pipeline["status"] = "complete"

        await _broadcast(pipeline_id, {
            "type": "progress", "stage": "complete", "percent": 100,
            "detail": "Analysis complete!",
        })
        await _broadcast(pipeline_id, {"type": "complete"})

    except Exception as e:
        traceback.print_exc()
        pipeline["status"] = "error"
        await _broadcast(pipeline_id, {
            "type": "error", "message": f"Pipeline failed: {str(e)}",
        })
    finally:
        asyncio.get_event_loop().call_later(600, lambda: _cleanup_pipeline(pipeline_id))


def _cleanup_pipeline(pipeline_id: str):
    try:
        pipeline_dir = UPLOAD_DIR / pipeline_id
        if pipeline_dir.exists():
            shutil.rmtree(pipeline_dir)
    except Exception:
        pass
