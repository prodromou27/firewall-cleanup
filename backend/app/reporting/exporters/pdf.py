"""PDF renderer — WeasyPrint over the shared HTML (page breaks, footers, page numbers via @page CSS)."""
from app.reporting.data import ReportData
from app.reporting.exporters.html import render as render_html


def render(data: ReportData) -> bytes:
    from weasyprint import HTML
    html = render_html(data)
    return HTML(string=html).write_pdf()
