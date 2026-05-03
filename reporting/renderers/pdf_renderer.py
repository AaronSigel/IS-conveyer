from __future__ import annotations

import os
import pathlib
import shutil
import subprocess


def _browser_candidates() -> list[str]:
    candidates = [
        "google-chrome",
        "chrome",
        "chromium",
        "chromium-browser",
        "msedge",
        "microsoft-edge",
    ]
    found = [path for name in candidates if (path := shutil.which(name))]
    if os.name == "nt":
        found.extend(
            [
                os.path.expandvars(r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
                os.path.expandvars(r"%LocalAppData%\Google\Chrome\Application\chrome.exe"),
                os.path.expandvars(r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"),
                os.path.expandvars(r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"),
            ]
        )
    return [path for path in found if pathlib.Path(path).exists()]


def _render_pdf_with_browser(html: pathlib.Path, pdf: pathlib.Path) -> None:
    browsers = _browser_candidates()
    if not browsers:
        raise RuntimeError("PDF rendering requires playwright or a headless Chrome/Edge executable")
    pdf = pdf.resolve()
    command = [
        browsers[0],
        "--headless",
        "--disable-gpu",
        "--no-sandbox",
        f"--print-to-pdf={pdf}",
        html.resolve().as_uri(),
    ]
    subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if not pdf.exists():
        raise RuntimeError(f"Browser PDF rendering completed but did not create {pdf}")


def render_pdf(html_path: str | pathlib.Path, output_path: str | pathlib.Path) -> None:
    """Render PDF from HTML."""
    html = pathlib.Path(html_path)
    pdf = pathlib.Path(output_path)
    pdf.parent.mkdir(parents=True, exist_ok=True)
    try:
        from playwright.sync_api import sync_playwright
    except ModuleNotFoundError:
        _render_pdf_with_browser(html, pdf)
        return

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()
        page.goto(html.resolve().as_uri(), wait_until="networkidle")
        page.pdf(
            path=str(pdf),
            format="A4",
            print_background=True,
            margin={"top": "14mm", "right": "14mm", "bottom": "14mm", "left": "14mm"},
        )
        browser.close()
