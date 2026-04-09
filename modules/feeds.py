import feedparser
import requests
import datetime
from datetime import timedelta
from config import FEEDS
from modules.classifier import classify_incident


def fetch_all_feeds(existing_links):
    new_entries = []

    for feed in FEEDS:
        feed_name = feed.get("name")
        feed_type = feed.get("type", "rss")
        
        # =========================
        # RSS FEEDS
        # =========================
        if feed_type != "json":
            try:
                parsed = feedparser.parse(feed["url"])
            except Exception as e:
                print(f"Error RSS {feed_name}: {e}")
                continue

            for entry in parsed.entries[:10]:
                if entry.link in existing_links:
                    continue

                summary = entry.get("summary", "")[:300]
                incident_type, severity = classify_incident(entry.title)

                new_entries.append({
                    "title": entry.title,
                    "link": entry.link,
                    "source": feed_name,
                    "type": incident_type,
                    "severity": severity,
                    "summary": summary,
                    "cvss_score": None,
                    "date": str(datetime.datetime.now())
                })

        # =========================
        # NVD JSON
        # =========================
        elif feed_name == "NVD":
            try:
                end_date = datetime.datetime.utcnow()
                start_date = end_date - timedelta(days=7)

                formatted_url = feed["url"].format(
                    start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
                    end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
                )

                response = requests.get(formatted_url, timeout=15)
                
                if response.status_code != 200:
                    print(f"NVD HTTP error {response.status_code}")
                    continue
                
                data = response.json()
                vulns = data.get("vulnerabilities", [])
                
                for vuln in vulns[:30]:
                    try:
                        # Normalizar: si es lista, tomar el primer elemento
                        if isinstance(vuln, list):
                            if len(vuln) == 0:
                                continue
                            vuln = vuln[0]
                        
                        if not isinstance(vuln, dict):
                            continue
                        
                        cve = vuln.get("cve")
                        if not cve or not isinstance(cve, dict):
                            continue
                        
                        cve_id = cve.get("id")
                        if not cve_id:
                            continue
                        
                        link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                        if link in existing_links:
                            continue
                        
                        # Descripción
                        desc_list = cve.get("descriptions", [])
                        description = ""
                        if desc_list and isinstance(desc_list, list):
                            first = desc_list[0]
                            if isinstance(first, dict):
                                description = first.get("value", "")[:300]
                        description = description.replace("\n", " ") if description else "No description"
                        
                        # CVSS
                        metrics = cve.get("metrics", {})
                        cvss_score = None
                        if isinstance(metrics, dict):
                            for metric_key in ["cvssMetricV31", "cvssMetricV30"]:
                                metric_list = metrics.get(metric_key)
                                if metric_list and isinstance(metric_list, list) and len(metric_list) > 0:
                                    metric_data = metric_list[0]
                                    if isinstance(metric_data, dict):
                                        cvss_data = metric_data.get("cvssData")
                                        if isinstance(cvss_data, dict):
                                            cvss_score = cvss_data.get("baseScore")
                                            if cvss_score:
                                                break
                        
                        # Severidad
                        if cvss_score:
                            if cvss_score >= 9.0:
                                severity = "🔴 CRITICAL"
                            elif cvss_score >= 7.0:
                                severity = "🟠 HIGH"
                            elif cvss_score >= 4.0:
                                severity = "🟢 MEDIUM"
                            else:
                                severity = "🔵 LOW"
                        else:
                            severity = "🟢 MEDIUM"
                        
                        new_entries.append({
                            "title": cve_id,
                            "link": link,
                            "source": feed_name,
                            "type": "Vulnerability",
                            "severity": severity,
                            "summary": description,
                            "cvss_score": cvss_score,
                            "date": str(datetime.datetime.now())
                        })
                        
                    except Exception as e:
                        continue
                        
            except Exception as e:
                print(f"NVD error: {e}")
                continue

    return new_entries
