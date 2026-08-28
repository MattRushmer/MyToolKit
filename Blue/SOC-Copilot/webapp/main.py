"""Run with: uvicorn webapp.main:app --reload (from the project root)."""
from __future__ import annotations

import tempfile
from pathlib import Path

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool

from soc_copilot.config import settings
from soc_copilot.ingest.adapters import ADAPTERS

BASE_DIR = Path(__file__).resolve().parent
app = FastAPI(title="SOC Copilot")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

_SUPPORTED_SUFFIXES = {".csv", ".json", ".ndjson", ".jsonl"}
_MAX_FILES = 20
_MAX_UPLOAD_BYTES = 25 * 1024 * 1024  # 25MB/file - generous for an MSP alert export, bounds memory/disk use
_COPY_CHUNK_BYTES = 1024 * 1024


def _save_upload_bounded(upload: UploadFile, destination: Path, max_bytes: int) -> bool:
    """Streams the upload to disk in fixed-size chunks, aborting as soon as
    max_bytes is exceeded rather than buffering an arbitrarily large upload
    in full first. Returns False (and leaves a partial/no file) on overflow."""
    total = 0
    with destination.open("wb") as handle:
        while True:
            chunk = upload.file.read(_COPY_CHUNK_BYTES)
            if not chunk:
                return True
            total += len(chunk)
            if total > max_bytes:
                return False
            handle.write(chunk)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(
        request,
        "index.html",
        {"has_llm_key": settings.has_llm_key, "adapters": sorted(ADAPTERS), "default_window": settings.correlation_window_minutes},
    )


@app.post("/run", response_class=HTMLResponse)
async def run(
    request: Request,
    client_id: str = Form(...),
    client_name: str = Form(...),
    tier: str = Form("standard"),
    window: str = Form(""),
    alert_files: list[UploadFile] = File(default_factory=list),
    alert_sources: list[str] = Form(default_factory=list),
):
    def error(message: str):
        return templates.TemplateResponse(
            request,
            "index.html",
            {"error": message, "has_llm_key": settings.has_llm_key, "adapters": sorted(ADAPTERS), "default_window": settings.correlation_window_minutes},
            status_code=400,
        )

    if len(alert_files) != len(alert_sources):
        return error("Each uploaded alert file must have exactly one source adapter.")
    uploaded = [(f, s) for f, s in zip(alert_files, alert_sources) if f and f.filename]
    if not uploaded:
        return error("Upload at least one alert export file.")
    if len(uploaded) > _MAX_FILES:
        return error(f"Too many files in one run (max {_MAX_FILES}). Split this into multiple runs.")

    correlation_window = None
    if window.strip():
        try:
            correlation_window = int(window.strip())
        except ValueError:
            return error(f"Correlation window must be a whole number of minutes, got '{window}'.")

    from soc_copilot.models import Client
    from soc_copilot.pipeline import ingest_files, run_pipeline
    from soc_copilot.report.digest import render_client_digest

    client = Client(client_id=client_id.strip(), name=client_name.strip(), criticality_tier=tier.strip() or "standard")

    with tempfile.TemporaryDirectory(prefix="soc-copilot-") as tmp:
        specs: list[tuple[Path, str]] = []
        for index, (upload, source) in enumerate(uploaded):
            suffix = Path(upload.filename).suffix.lower()
            if suffix not in _SUPPORTED_SUFFIXES:
                continue
            destination = Path(tmp) / f"{index}-{Path(upload.filename).name}"
            if not _save_upload_bounded(upload, destination, _MAX_UPLOAD_BYTES):
                return error(f"'{upload.filename}' exceeds the {_MAX_UPLOAD_BYTES // (1024 * 1024)}MB per-file upload limit.")
            specs.append((destination, source if source in ADAPTERS else "generic"))
        if not specs:
            return error(f"None of the uploaded files had a supported extension ({', '.join(sorted(_SUPPORTED_SUFFIXES))}).")

        alerts, warnings = ingest_files(specs, client.client_id)
        if not alerts:
            return error("No alerts could be parsed from the uploaded file(s). " + " ".join(warnings[:3]))

        result = await run_in_threadpool(run_pipeline, alerts, client, correlation_window)

    digest = render_client_digest(result)
    return templates.TemplateResponse(request, "result.html", {"result": result, "digest": digest, "has_llm_key": settings.has_llm_key})


@app.get("/health")
async def health():
    return {"status": "ok"}
