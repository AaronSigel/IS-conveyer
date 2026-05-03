from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool

from web import jobs, runs
from web.filters import PRESETS, apply_filters, filters_from_form, normalize_findings
from web.reports import create_export


app = FastAPI(title="IS Conveyer Web UI")
BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


def default_hosts() -> list[str]:
    return ["target1", "target2"]


@app.get("/health")
def health() -> dict[str, object]:
    return {"status": "ok", "runs_dir_exists": runs.RUNS_DIR.exists()}


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    return templates.TemplateResponse(request, "dashboard.html", {"runs": runs.list_runs(), "active_run_id": jobs.active_run_id()})


@app.get("/scans/new", response_class=HTMLResponse)
def scan_new(request: Request):
    return templates.TemplateResponse(request, "scan_new.html", {"hosts": default_hosts(), "profile_id": runs.PROFILE_ID})


@app.post("/scans")
async def scans(request: Request):
    form = await request.form()
    hosts = [host for host in form.getlist("hosts") if host in default_hosts()]
    if not hosts:
        hosts = default_hosts()
    ok, result = jobs.start_scan(hosts, create_default_export=form.get("create_default_export") == "on")
    if not ok:
        return templates.TemplateResponse(
            request,
            "scan_new.html",
            {"hosts": default_hosts(), "profile_id": runs.PROFILE_ID, "error": result},
            status_code=409,
        )
    return RedirectResponse(f"/scans/{result}", status_code=303)


@app.get("/scans/{run_id}", response_class=HTMLResponse)
def scan_status(request: Request, run_id: str):
    return templates.TemplateResponse(request, "scan_status.html", {"metadata": runs.load_metadata(run_id), "run_id": run_id})


@app.get("/scans/{run_id}/logs", response_class=PlainTextResponse)
def scan_logs(run_id: str):
    path = runs.run_dir(run_id) / "logs.txt"
    return path.read_text(encoding="utf-8") if path.exists() else ""


@app.get("/reports", response_class=HTMLResponse)
def reports_list(request: Request):
    return templates.TemplateResponse(request, "reports_list.html", {"runs": runs.list_runs()})


@app.get("/reports/{run_id}", response_class=HTMLResponse)
def report_detail(request: Request, run_id: str):
    metadata = runs.load_metadata(run_id)
    findings = normalize_findings(runs.load_findings(run_id))
    return templates.TemplateResponse(
        request,
        "report_detail.html",
        {
            "metadata": metadata,
            "findings": findings[:300],
            "findings_count": len(findings),
            "preview_summary": runs.summarize_findings(findings),
            "exports": runs.list_exports(run_id),
            "presets": PRESETS,
        },
    )


@app.get("/reports/{run_id}/json")
def report_json(run_id: str):
    path = runs.run_dir(run_id) / "unified-findings.json"
    return FileResponse(path, media_type="application/json", filename=f"{run_id}-unified-findings.json")


@app.get("/reports/{run_id}/normalized")
def report_normalized_json(run_id: str):
    path = runs.run_dir(run_id) / "normalized_report.json"
    if not path.exists():
        return PlainTextResponse("normalized_report.json is not available for this run", status_code=404)
    return FileResponse(path, media_type="application/json", filename=f"{run_id}-normalized_report.json")


@app.get("/reports/{run_id}/html")
def report_html(run_id: str):
    path = runs.run_dir(run_id) / "technical_report.html"
    if not path.exists():
        return PlainTextResponse("technical_report.html is not available for this run", status_code=404)
    return FileResponse(path, media_type="text/html", filename=f"{run_id}-technical_report.html")


@app.get("/reports/{run_id}/pdf")
def report_pdf(run_id: str):
    path = runs.run_dir(run_id) / "technical_report.pdf"
    if not path.exists():
        return PlainTextResponse("technical_report.pdf is not available for this run. Check logs for PDF renderer availability.", status_code=404)
    return FileResponse(path, media_type="application/pdf", filename=f"{run_id}-technical_report.pdf")


@app.get("/reports/{run_id}/raw/{artifact}")
def report_raw_artifact(run_id: str, artifact: str):
    allowed = {
        "wazuh-sca": ("wazuh-sca.json", "application/json"),
        "wazuh-vulnerabilities": ("wazuh-vulnerabilities.json", "application/json"),
    }
    if artifact not in allowed:
        return PlainTextResponse("Unknown raw artifact", status_code=404)
    filename, media_type = allowed[artifact]
    path = runs.run_dir(run_id) / "raw" / filename
    if not path.exists():
        return PlainTextResponse(f"{filename} is not available for this run", status_code=404)
    return FileResponse(path, media_type=media_type, filename=f"{run_id}-{filename}")


@app.post("/reports/{run_id}/preview")
async def report_preview(run_id: str, request: Request):
    form = dict(await request.form())
    filters = filters_from_form(form)
    findings = normalize_findings(runs.load_findings(run_id))
    filtered = apply_filters(findings, filters)
    return JSONResponse({"filters": filters, "summary": runs.summarize_findings(filtered), "total_before": len(findings), "total_after": len(filtered)})


@app.post("/reports/{run_id}/exports")
async def report_export(run_id: str, request: Request):
    form = dict(await request.form())
    title = str(form.get("title") or "Split reports")
    report_mode = str(form.get("report_mode") or "split")
    export = await run_in_threadpool(create_export, run_id, title, filters_from_form(form), None, report_mode)
    return RedirectResponse(f"/reports/{run_id}/exports/{export['id']}", status_code=303)


@app.get("/reports/{run_id}/exports/{export_id}", response_class=HTMLResponse)
def export_detail(request: Request, run_id: str, export_id: str):
    runs.validate_component(export_id, "export id")
    export = runs.read_json(runs.run_dir(run_id) / "exports" / export_id / "export.json", {})
    return templates.TemplateResponse(request, "export_detail.html", {"metadata": runs.load_metadata(run_id), "export": export, "run_id": run_id})


@app.get("/reports/{run_id}/exports/{export_id}/html")
def export_html(run_id: str, export_id: str):
    runs.validate_component(export_id, "export id")
    export = runs.read_json(runs.run_dir(run_id) / "exports" / export_id / "export.json", {})
    filename = (export.get("files") or {}).get("html", "technical_report.html")
    path = runs.run_dir(run_id) / "exports" / export_id / filename
    return FileResponse(path, media_type="text/html", filename=f"{run_id}-{export_id}.html")


@app.get("/reports/{run_id}/exports/{export_id}/pdf")
def export_pdf(run_id: str, export_id: str):
    runs.validate_component(export_id, "export id")
    export = runs.read_json(runs.run_dir(run_id) / "exports" / export_id / "export.json", {})
    filename = (export.get("files") or {}).get("pdf", "technical_report.pdf")
    path = runs.run_dir(run_id) / "exports" / export_id / filename
    return FileResponse(path, media_type="application/pdf", filename=f"{run_id}-{export_id}.pdf")


@app.get("/reports/{run_id}/exports/{export_id}/{report_id}/html")
def export_report_html(run_id: str, export_id: str, report_id: str):
    runs.validate_component(export_id, "export id")
    runs.validate_component(report_id, "report id")
    export = runs.read_json(runs.run_dir(run_id) / "exports" / export_id / "export.json", {})
    report = (export.get("reports") or {}).get(report_id, {})
    filename = (report.get("files") or {}).get("html")
    if not filename:
        return PlainTextResponse("Report HTML file not found", status_code=404)
    path = runs.run_dir(run_id) / "exports" / export_id / filename
    return FileResponse(path, media_type="text/html", filename=f"{run_id}-{export_id}-{report_id}.html")


@app.get("/reports/{run_id}/exports/{export_id}/{report_id}/pdf")
def export_report_pdf(run_id: str, export_id: str, report_id: str):
    runs.validate_component(export_id, "export id")
    runs.validate_component(report_id, "report id")
    export = runs.read_json(runs.run_dir(run_id) / "exports" / export_id / "export.json", {})
    report = (export.get("reports") or {}).get(report_id, {})
    filename = (report.get("files") or {}).get("pdf")
    if not filename:
        return PlainTextResponse("Report PDF file not found", status_code=404)
    path = runs.run_dir(run_id) / "exports" / export_id / filename
    return FileResponse(path, media_type="application/pdf", filename=f"{run_id}-{export_id}-{report_id}.pdf")
