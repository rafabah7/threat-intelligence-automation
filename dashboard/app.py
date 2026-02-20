from flask import Flask, render_template_string, request
import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "data", "soc.db")

app = Flask(__name__)

@app.route("/")
def index():

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Total alertas
    cursor.execute("SELECT COUNT(*) FROM alerts")
    total = cursor.fetchone()[0]

    # Conteo por severidad
    cursor.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")
    severity_data = cursor.fetchall()

    # Filtro por severidad
    severity_filter = request.args.get("sev")

    if severity_filter:
        cursor.execute("""
            SELECT title, severity, cvss_score, date
            FROM alerts
            WHERE severity = ?
            ORDER BY date DESC
            LIMIT 20
        """, (severity_filter,))
    else:
        cursor.execute("""
            SELECT title, severity, cvss_score, date
            FROM alerts
            ORDER BY date DESC
            LIMIT 20
        """)

    rows = cursor.fetchall()
    conn.close()

    html = """
    <html>
    <head>
        <title>Threat Intelligence Dashboard</title>
        <meta http-equiv="refresh" content="60">
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

        <style>
            body { font-family: Arial; background-color: #0f172a; color: white; padding: 20px; }
            h1 { color: #38bdf8; }
            .card { background: #1e293b; padding: 15px; margin: 10px 0; border-radius: 8px; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            th, td { padding: 10px; border-bottom: 1px solid #334155; }
            th { background-color: #1e293b; }
            .btn { color:white; padding:10px; background:#38bdf8; border-radius:5px; text-decoration:none; }
        </style>
    </head>
    <body>
        <h1>Threat Intelligence Dashboard</h1>

        {% set sev_labels = severity_data | map(attribute=0) | list %}

        {% if 'CRITICAL' in sev_labels %}
        <div style="background:#dc2626; padding:20px; border-radius:10px; margin-bottom:20px; text-align:center; font-size:24px; font-weight:bold;">
            ⚠️ CRITICAL VULNERABILITIES DETECTED
        </div>
        {% endif %}

        <div class="card">
            <h2>Total Alerts: {{ total }}</h2>
        </div>

        <div class="card">
            <h3>Severity Breakdown</h3>
            {% for sev in severity_data %}
                <p>{{ sev[0] }} : {{ sev[1] }}</p>
            {% endfor %}
        </div>

        <div class="card">
            <h3>Severity Chart</h3>
            <canvas id="severityChart"></canvas>
        </div>

        <div class="card">
            <form method="get">
                <label>Filter by severity:</label>
                <select name="sev" onchange="this.form.submit()">
                    <option value="">All</option>
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                </select>
            </form>

            <br>

            <a class="btn" href="/export">Export CSV</a>
        </div>

        <div class="card">
            <h3>Latest Alerts</h3>
            <table>
                <tr>
                    <th>Title</th>
                    <th>Severity</th>
                    <th>CVSS</th>
                    <th>Date</th>
                </tr>
                {% for row in rows %}
                <tr>
                    <td>{{ row[0] }}</td>
                    <td>{{ row[1] }}</td>
                    <td>{{ row[2] }}</td>
                    <td>{{ row[3] }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>

        <script>
            const ctx = document.getElementById('severityChart').getContext('2d');
            const severityLabels = {{ severity_data | map(attribute=0) | list }};
            const severityCounts = {{ severity_data | map(attribute=1) | list }};

            new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: severityLabels,
                    datasets: [{
                        label: 'Alerts by Severity',
                        data: severityCounts,
                        backgroundColor: ['#ef4444', '#f97316', '#eab308', '#22c55e']
                    }]
                }
            });
        </script>

    </body>
    </html>
    """

    return render_template_string(html, total=total, severity_data=severity_data, rows=rows)


@app.route("/export")
def export_csv():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT title, severity, cvss_score, date FROM alerts ORDER BY date DESC")
    rows = cursor.fetchall()
    conn.close()

    csv_data = "title,severity,cvss,date\\n"
    for r in rows:
        csv_data += f"{r[0]},{r[1]},{r[2]},{r[3]}\\n"

    return csv_data, 200, {
        "Content-Type": "text/csv",
        "Content-Disposition": "attachment; filename=alerts.csv"
    }


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
