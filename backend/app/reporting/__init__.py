"""PolicyInsight reporting package.

A single shared report-data model (data.py) is built once from existing
analysis data and handed to every exporter (HTML, PDF, DOCX, XLSX, CSV, JSON).
Strictly read-only: nothing here changes firewall configuration.
"""
