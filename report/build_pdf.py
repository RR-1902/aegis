"""Render report.html to AEGIS_Project_Report.pdf with headless Chromium (Playwright).

usage: python report/build_pdf.py
"""
from pathlib import Path
from playwright.sync_api import sync_playwright

HERE = Path(__file__).resolve().parent
FOOTER = (
    "<div style=\"width:100%;padding:0 19mm;font-family:Segoe UI,Arial,sans-serif;font-size:8px;"
    "color:#8792ab;display:flex;justify-content:space-between\">"
    "<span>AEGIS: Explainable Network Intrusion Detection and Response</span>"
    "<span><span class=\"pageNumber\"></span> / <span class=\"totalPages\"></span></span></div>"
)

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page()
    page.goto((HERE / "report.html").as_uri())
    page.wait_for_load_state("networkidle")
    page.evaluate("document.fonts.ready")
    page.pdf(
        path=str(HERE / "AEGIS_Project_Report.pdf"),
        prefer_css_page_size=True,
        print_background=True,
        display_header_footer=True,
        header_template="<span></span>",
        footer_template=FOOTER,
    )
    browser.close()
print("wrote", HERE / "AEGIS_Project_Report.pdf")
