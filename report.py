"""
Builds dashboard.html from alerts.jsonl: totals, alerts per rule, top sources, the latest alerts
and what the response mechanism did about each one.
Run it after suricata_watch.py has saved some alerts. It needs no extra libraries and opens in your browser.
"""

import json
import webbrowser
from collections import Counter
from datetime import datetime
from html import escape
from pathlib import Path

ALERT_FILE = "alerts.jsonl"
DASHBOARD_FILE = "dashboard.html"
COLORS = {"HIGH": "#c5221f", "MEDIUM": "#b06000", "INFO": "#1a73e8"}
RESPONSE_COLORS = {"blocked": "#c5221f", "already blocked": "#c5221f", "dry run": "#b06000"}

CSS = """
*{box-sizing:border-box}
body{margin:0;padding:28px 16px;background:#f1f3f6;color:#1f2933;font-family:Segoe UI,Arial,sans-serif}
.page{max-width:1000px;margin:0 auto}
h1{margin:0 0 4px;font-size:28px}
h2{margin:0 0 14px;font-size:18px}
.sub,.muted{color:#5f6b7a}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin:22px 0}
.card,.panel{background:#fff;border:1px solid #d9dee5;border-radius:10px;padding:16px 18px}
.card b{display:block;font-size:32px;line-height:1.2}
.panel{margin-bottom:18px}
.row{display:grid;grid-template-columns:minmax(120px,260px) 1fr 40px;gap:12px;align-items:center;margin:9px 0;font-size:14px}
.bar{background:#e8ebf0;border-radius:6px;height:16px;overflow:hidden}
.bar span{display:block;height:100%}
.count{text-align:right;font-weight:600}
.table-wrap{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:13.5px}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid #e5e8ed;vertical-align:top}
th{color:#5f6b7a;font-weight:600}
.badge{display:inline-block;color:#fff;border-radius:5px;padding:2px 8px;font-size:12px;font-weight:700}
code{font-family:Consolas,monospace;font-size:12.5px}
.break{overflow-wrap:anywhere}
.nowrap{white-space:nowrap}
"""


def load_alerts():
    alerts = []
    try:
        with open(ALERT_FILE, encoding="utf-8") as file:
            for line in file:
                try:
                    alerts.append(json.loads(line))
                except ValueError:
                    pass   # skip a damaged line
    except FileNotFoundError:
        pass
    return alerts


def bars(items, color):
    """Horizontal bar chart. `items` is a list of (label, count) pairs."""
    if not items:
        return "<p class='muted'>Nothing yet.</p>"
    biggest = max(count for _, count in items)
    rows = []
    for label, count in items:
        width = round(100 * count / biggest)
        rows.append(
            f"<div class='row'><div>{escape(str(label))}</div>"
            f"<div class='bar'><span style='width:{width}%;background:{color}'></span></div>"
            f"<div class='count'>{count}</div></div>"
        )
    return "\n".join(rows)


def build_page(alerts):
    by_severity = Counter(a.get("severity", "") for a in alerts)
    by_rule = Counter(a.get("rule", "") for a in alerts).most_common()
    by_source = Counter(a.get("src", "") for a in alerts).most_common(5)

    cards = [("Total alerts", len(alerts), "#1f2933")]
    cards += [(name.title(), by_severity.get(name, 0), COLORS[name]) for name in ("HIGH", "MEDIUM", "INFO")]
    cards += [("Different sources", len(set(a.get("src", "") for a in alerts)), "#1f2933")]
    cards_html = "".join(
        f"<div class='card'><b style='color:{color}'>{value}</b><span class='muted'>{escape(name)}</span></div>"
        for name, value, color in cards
    )

    rows = []
    for a in reversed(alerts[-50:]):
        color = COLORS.get(a.get("severity", ""), "#5f6b7a")
        response = str(a.get("response", "-"))
        rows.append(
            "<tr>"
            f"<td class='nowrap'>{escape(a.get('time', ''))}</td>"
            f"<td><span class='badge' style='background:{color}'>{escape(a.get('severity', ''))}</span></td>"
            f"<td>{escape(a.get('rule', ''))}</td>"
            f"<td class='nowrap'><code>{escape(a.get('src', ''))}</code></td>"
            f"<td class='nowrap'><code>{escape(a.get('dst', ''))}</code></td>"
            f"<td><code class='break'>{escape(a.get('details', ''))}</code></td>"
            f"<td class='nowrap' style='color:{RESPONSE_COLORS.get(response, '#5f6b7a')}'>{escape(response)}</td>"
            "</tr>"
        )
    table = ("<div class='table-wrap'><table><tr><th>Time</th><th>Severity</th><th>Rule</th>"
             "<th>Source</th><th>Target</th><th>Details</th><th>Response</th></tr>" + "".join(rows) + "</table></div>"
             if rows else "<p class='muted'>No alerts yet. Run suricata_watch.py first.</p>")

    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>Suricata IDS Dashboard</title><style>{CSS}</style></head><body><div class='page'>"
        "<h1>Network IDS Dashboard</h1>"
        f"<p class='sub'>Suricata alerts, built {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} from {escape(ALERT_FILE)}</p>"
        f"<div class='cards'>{cards_html}</div>"
        f"<div class='panel'><h2>Alerts by rule</h2>{bars(by_rule, '#1a73e8')}</div>"
        f"<div class='panel'><h2>Top sources</h2>{bars(by_source, '#c5221f')}</div>"
        f"<div class='panel'><h2>Latest alerts</h2>{table}</div>"
        "</div></body></html>"
    )


if __name__ == "__main__":
    alerts = load_alerts()
    with open(DASHBOARD_FILE, "w", encoding="utf-8") as file:
        file.write(build_page(alerts))
    print(f"Dashboard built from {len(alerts)} alerts: {DASHBOARD_FILE}")
    webbrowser.open(Path(DASHBOARD_FILE).resolve().as_uri())
