from flask import Flask
import sqlite3

app = Flask(__name__)

@app.route("/")
def home():

    conn = sqlite3.connect("soc.db")
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM alerts")
    total = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity LIKE '%CRITICAL%'")
    critical = cursor.fetchone()[0]

    conn.close()

    return f"""
    <h1>Cyber Threat Monitor Dashboard</h1>
    <p>Total Alerts: {total}</p>
    <p>Critical Alerts: {critical}</p>
    """

if __name__ == "__main__":
    app.run(debug=True)
