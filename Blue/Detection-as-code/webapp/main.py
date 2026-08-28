"""Run with: uvicorn webapp.main:app --reload (from the project root)."""
from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from detection_forge.config import settings

BASE_DIR = Path(__file__).resolve().parent
VALID_TARGETS = {"sigma", "splunk", "elasticsearch", "wazuh"}
app = FastAPI(title="Detection Forge")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


def _context(result):
    rule = result.rule
    samples = []
    if result.backtest:
        samples = [{"line_number": item.line_number, "selections": item.matched_selection_names, "record": json.dumps(item.record, indent=2, default=str)} for item in result.backtest.matched_events[:5]]
    return {
        "result": result,
        "rule": rule,
        "samples": samples,
        "band_class": (result.noise.band if result.noise else "unknown"),
    }


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request, "index.html", {"has_llm_key": settings.has_llm_key})


@app.post("/run", response_class=HTMLResponse)
async def run(
    request: Request,
    cti_text: str = Form(""),
    cti_file: UploadFile | None = File(None),
    log_files: list[UploadFile] = File([]),
    export_targets: list[str] = Form(["sigma"]),
):
    text = cti_text.strip()
    source_name = "pasted-report"
    if not text and cti_file and cti_file.filename:
        text = (await cti_file.read()).decode("utf-8", errors="replace").strip()
        source_name = cti_file.filename
    if not text:
        return templates.TemplateResponse(request, "index.html", {"error": "Paste CTI text or upload a CTI report.", "has_llm_key": settings.has_llm_key}, status_code=400)
    targets = [target for target in export_targets if target in VALID_TARGETS] or ["sigma"]
    with tempfile.TemporaryDirectory(prefix="detection-forge-") as tmp:
        log_paths: list[Path] = []
        for upload in log_files:
            if not upload.filename or Path(upload.filename).suffix.lower() not in {".json", ".ndjson", ".jsonl"}:
                continue
            safe_name = Path(upload.filename).name
            destination = Path(tmp) / safe_name
            with destination.open("wb") as handle:
                shutil.copyfileobj(upload.file, handle)
            log_paths.append(destination)
        try:
            from detection_forge.pipeline import run_pipeline
            result = run_pipeline(text, source_name=source_name, log_file_paths=log_paths, export_targets=targets)
        except Exception as exc:
            from detection_forge.llm.anthropic_client import LLMNotConfiguredError
            message = "ANTHROPIC_API_KEY is not configured. Set it as described in README.md, then restart the server." if isinstance(exc, LLMNotConfiguredError) else f"Pipeline stage failed: {exc}"
            return templates.TemplateResponse(request, "index.html", {"error": message, "has_llm_key": settings.has_llm_key}, status_code=400)
    return templates.TemplateResponse(request, "result.html", _context(result))


@app.get("/health")
async def health():
    return {"status": "ok"}
