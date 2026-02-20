from config import INCIDENT_TYPES, SEVERITY_RULES

def classify_incident(title):
    title_lower = title.lower()

    incident_type = "General"
    severity = "🟢 MEDIUM"

    for keyword, category in INCIDENT_TYPES.items():
        if keyword in title_lower:
            incident_type = category
            break

    for level, keywords in SEVERITY_RULES.items():
        for word in keywords:
            if word in title_lower:
                if level == "critical":
                    severity = "🔴 CRITICAL"
                elif level == "high":
                    severity = "🟠 HIGH"
                elif level == "medium":
                    severity = "🟢 MEDIUM"

    return incident_type, severity
