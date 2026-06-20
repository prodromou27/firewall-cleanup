"""HTML renderer — the single styled HTML used for both HTML and PDF exports.

Jinja2 with autoescape ON: all finding/rule/user text is HTML-escaped, closing
report-content injection risks. Narrative text keeps line breaks via CSS.
"""
from jinja2 import Environment, select_autoescape

from app.reporting.data import ReportData

_env = Environment(autoescape=select_autoescape(default=True, default_for_string=True))

_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>{{ b.report_title }}</title>
<style>
  @page { size: A4; margin: 22mm 18mm 20mm 18mm;
    @bottom-center { content: "{{ b.confidentiality }} — page " counter(page) " of " counter(pages);
      font-size: 8pt; color: #888; } }
  * { box-sizing: border-box; }
  body { font-family: 'Helvetica Neue', Arial, sans-serif; color: #1f2937; font-size: 11pt; line-height: 1.5; margin: 0; }
  h1,h2,h3 { color: {{ b.accent_color }}; }
  h2 { border-bottom: 2px solid {{ b.accent_color }}; padding-bottom: 4px; margin-top: 28px; font-size: 16pt; }
  h3 { font-size: 13pt; margin-top: 18px; }
  .cover { text-align: center; padding-top: 28mm; page-break-after: always; }
  .cover .title { font-size: 28pt; font-weight: 800; color: {{ b.accent_color }}; margin: 10px 0; }
  .cover .subtitle { font-size: 14pt; color: #6b7280; }
  .cover .meta { margin-top: 30mm; font-size: 11pt; color: #374151; }
  .conf { display: inline-block; margin-top: 14px; padding: 4px 12px; border: 1px solid {{ b.accent_color }};
    color: {{ b.accent_color }}; border-radius: 4px; font-weight: 700; letter-spacing: .05em; font-size: 9pt; }
  .logo { max-height: 60px; max-width: 240px; margin: 6px auto; display: block; }
  table { width: 100%; border-collapse: collapse; margin: 10px 0; font-size: 9.5pt; }
  th { background: {{ b.accent_color }}; color: #fff; text-align: left; padding: 6px 8px; }
  td { border-bottom: 1px solid #e5e7eb; padding: 5px 8px; vertical-align: top; }
  tr:nth-child(even) td { background: #f9fafb; }
  .text { white-space: pre-wrap; }
  .kpis { display: flex; flex-wrap: wrap; gap: 10px; margin: 12px 0; }
  .kpi { border: 1px solid #e5e7eb; border-radius: 8px; padding: 10px 14px; min-width: 110px; }
  .kpi .n { font-size: 20pt; font-weight: 800; color: {{ b.accent_color }}; }
  .kpi .l { font-size: 8.5pt; color: #6b7280; text-transform: uppercase; }
  .sev { font-weight: 700; padding: 1px 6px; border-radius: 3px; font-size: 8.5pt; color: #fff; }
  .sev-Critical { background:#b91c1c; } .sev-High { background:#dc2626; }
  .sev-Medium { background:#d97706; } .sev-Low { background:#2563eb; } .sev-Informational { background:#6b7280; }
  .disclaimer { background:#f3f4f6; border-left:4px solid {{ b.accent_color }}; padding:12px 16px; font-size:9.5pt; }
  .section { page-break-inside: avoid; }
  footer.brandfoot { margin-top: 26px; border-top:1px solid #e5e7eb; padding-top:8px; font-size:8.5pt; color:#9ca3af; }
</style></head><body>

<div class="cover">
  {% if b.company_logo %}<img class="logo" src="{{ b.company_logo }}">{% endif %}
  <div class="title">{{ b.report_title }}</div>
  {% if b.cover_subtitle %}<div class="subtitle">{{ b.cover_subtitle }}</div>{% endif %}
  {% if b.customer_logo %}<img class="logo" src="{{ b.customer_logo }}">{% endif %}
  <div class="meta">
    <div><strong>Customer:</strong> {{ m.customer_name }}</div>
    <div><strong>Firewall:</strong> {{ m.firewall_name }} ({{ m.vendor }})</div>
    <div><strong>Analysis date:</strong> {{ m.analysis_date }}</div>
    <div><strong>Generated:</strong> {{ m.generated_date }}</div>
    {% if b.prepared_by %}<div><strong>Prepared by:</strong> {{ b.prepared_by }}</div>{% endif %}
    <div class="conf">{{ b.confidentiality }}</div>
    {% if b.cover_custom_text %}<div class="text" style="margin-top:14px">{{ b.cover_custom_text }}</div>{% endif %}
  </div>
</div>

{% for s in sections %}
  {% if s.key == 'cover_page' %}{# rendered above #}
  {% elif s.type == 'doc_control' %}
    <div class="section"><h2>Document Control</h2>
      <table><tr><th>Field</th><th>Value</th></tr>
        <tr><td>Report title</td><td>{{ b.report_title }}</td></tr>
        <tr><td>Customer</td><td>{{ m.customer_name }}</td></tr>
        <tr><td>Firewall</td><td>{{ m.firewall_name }}</td></tr>
        <tr><td>Vendor</td><td>{{ m.vendor }}</td></tr>
        <tr><td>Analysis date</td><td>{{ m.analysis_date }}</td></tr>
        <tr><td>Generated</td><td>{{ m.generated_date }}</td></tr>
        <tr><td>Classification</td><td>{{ b.confidentiality }}</td></tr>
      </table></div>
  {% elif s.type == 'text' %}
    {% if s.text %}<div class="section"><h2>{{ s.name }}</h2><div class="text">{{ s.text }}</div></div>{% endif %}
  {% elif s.type == 'metrics' %}
    <div class="section"><h2>{{ s.name }}</h2>
      <div class="kpis">
        <div class="kpi"><div class="n">{{ m.total_findings }}</div><div class="l">Findings</div></div>
        <div class="kpi"><div class="n">{{ m.critical_findings }}</div><div class="l">Critical</div></div>
        <div class="kpi"><div class="n">{{ m.high_findings }}</div><div class="l">High</div></div>
        <div class="kpi"><div class="n">{{ m.total_rules }}</div><div class="l">Rules</div></div>
        <div class="kpi"><div class="n">{{ m.total_objects }}</div><div class="l">Objects</div></div>
        {% if m.policy_score != '' %}<div class="kpi"><div class="n">{{ m.policy_score }}</div><div class="l">Health score</div></div>{% endif %}
      </div>
      {% if s.key == 'findings_by_severity' %}
        <table><tr><th>Severity</th><th>Count</th></tr>
        {% for sev in ['Critical','High','Medium','Low','Informational'] %}
          <tr><td><span class="sev sev-{{ sev }}">{{ sev }}</span></td><td>{{ severity_counts.get(sev, 0) }}</td></tr>
        {% endfor %}</table>
      {% elif s.key == 'findings_by_category' %}
        <table><tr><th>Category</th><th>Count</th></tr>
        {% for cat, n in category_counts.items() %}<tr><td>{{ cat }}</td><td>{{ n }}</td></tr>{% endfor %}</table>
      {% endif %}
    </div>
  {% elif s.type == 'findings' %}
    <div class="section"><h2>{{ s.name }}</h2>
      {% if s.findings %}
      <table><tr><th>Severity</th><th>Type</th><th>Title</th><th>Recommendation</th><th>Conf.</th></tr>
        {% for f in s.findings %}
        <tr><td><span class="sev sev-{{ f.severity }}">{{ f.severity }}</span></td>
          <td>{{ f.finding_type_label }}</td><td>{{ f.title }}</td>
          <td>{{ f.recommendation }}</td><td>{{ f.confidence }}</td></tr>
        {% endfor %}</table>
      {% else %}<p style="color:#6b7280">No findings in this category.</p>{% endif %}
    </div>
  {% elif s.type == 'appendix' and s.key == 'full_rulebase' %}
    <div class="section"><h2>{{ s.name }}</h2>
      <table><tr><th>#</th><th>Name</th><th>Source</th><th>Dest</th><th>Service</th><th>Action</th><th>Log</th><th>Hits</th></tr>
      {% for r in rules %}<tr><td>{{ r.rule_number }}</td><td>{{ r.rule_name }}</td><td>{{ r.sources }}</td>
        <td>{{ r.destinations }}</td><td>{{ r.services }}</td><td>{{ r.action }}</td><td>{{ r.logging }}</td><td>{{ r.hit_count }}</td></tr>{% endfor %}
      </table></div>
  {% elif s.type == 'appendix' and s.key == 'full_object_inventory' %}
    <div class="section"><h2>{{ s.name }}</h2>
      <table><tr><th>Name</th><th>Type</th><th>Value</th><th>Members</th></tr>
      {% for o in objects %}<tr><td>{{ o.object_name }}</td><td>{{ o.object_type }}</td><td>{{ o.value }}</td><td>{{ o.members }}</td></tr>{% endfor %}
      </table></div>
  {% endif %}
{% endfor %}

<footer class="brandfoot">{{ b.company_name }}{% if b.footer_text %} · {{ b.footer_text }}{% endif %} · {{ b.confidentiality }}</footer>
</body></html>"""


def render(data: ReportData) -> str:
    tmpl = _env.from_string(_TEMPLATE)
    return tmpl.render(
        b=data.branding, m=data.meta, sections=data.sections,
        severity_counts=data.severity_counts, category_counts=data.category_counts,
        rules=data.rules, objects=data.objects,
    )
