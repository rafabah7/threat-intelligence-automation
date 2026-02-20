import feedparser
import requests
import datetime
from datetime import timedelta
from config import FEEDS
from modules.classifier import classify_incident

def fetch_all_feeds(existing_links):

    new_entries = []

    for feed in FEEDS:

        # =========================
        # RSS FEEDS
        # =========================
        if feed.get("type") != "json":

            parsed = feedparser.parse(feed["url"])

            for entry in parsed.entries[:10]:

                if entry.link in existing_links:
                    continue

                summary = entry.get("summary", "")[:300]
                incident_type, severity = classify_incident(entry.title)

                new_entries.append({
                    "title": entry.title,
                    "link": entry.link,
                    "source": feed["name"],
                    "type": incident_type,
                    "severity": severity,
                    "summary": summary,
                    "cvss_score": None,
                    "date": str(datetime.datetime.now())
                })

        # =========================
        # NVD JSON (Últimos 7 días)
        # =========================
        else:
            try:
                end_date = datetime.datetime.utcnow()
                start_date = end_date - timedelta(days=7)

                formatted_url = feed["url"].format(
                    start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
                    end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
                )

                response = requests.get(formatted_url, timeout=10)
                data = response.json()

                for vuln in data.get("vulnerabilities", [])[:20]:

                    cve = vuln.get("cve", {})
                    cve_id = cve.get("id", "Unknown")

                    raw_description = cve.get("descriptions", [{}])[0].get("value", "")
                    description = raw_description[:350].replace("\n", " ")

                    link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

                    if link in existing_links:
                        continue

                    # ===== EXTRAER CVSS =====
                    metrics = cve.get("metrics", {})
                    cvss_score = None

                    if "cvssMetricV31" in metrics:
                        cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                    elif "cvssMetricV30" in metrics:
                        cvss_score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
                    elif "cvssMetricV2" in metrics:
                        cvss_score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

                    # ===== CALCULAR SEVERIDAD =====
                    if cvss_score is not None:
                        if cvss_score >= 9:
                            severity = "🔴 CRITICAL"
                        elif cvss_score >= 7:
                            severity = "🟠 HIGH"
                        elif cvss_score >= 4:
                            severity = "🟢 MEDIUM"
                        else:
                            severity = "🔵 LOW"
                    else:
                        severity = "🟢 MEDIUM"

                    new_entries.append({
                        "title": cve_id,
                        "link": link,
                        "source": feed["name"],
                        "type": "Vulnerability",
                        "severity": severity,
                        "summary": description,
                        "cvss_score": cvss_score,
                        "date": str(datetime.datetime.now())
                    })

            except Exception as e:
                print(f"Error JSON feed {feed['name']}: {e}")

    return new_entries
