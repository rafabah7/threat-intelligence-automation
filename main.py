from modules.storage import load_history
from modules.feeds import fetch_all_feeds
from modules.notifier import send_telegram
from database import init_db, insert_alert

init_db()

def format_alert(entry):
    return f"""
<b>{entry['severity']}  |  {entry['type']}</b>
🔎 <b>Fuente:</b> {entry['source']}

📰 <b>Título:</b> {entry['title']}
📝 <b>Resumen:</b> {entry['summary']}
🔢 <b>CVSS:</b> {entry.get('cvss_score', 'N/A')}
🔗 <b>Link:</b> {entry['link']}
"""

def main():

    history = load_history()
    existing_links = [item["link"] for item in history]

    new_entries = fetch_all_feeds(existing_links)

    for entry in new_entries:
        if entry["severity"] not in ["🔴 CRITICAL", "🟠 HIGH"]:
            continue

        message = format_alert(entry)
        print(message)
        send_telegram(message)
        insert_alert(entry)

    print(f"\nTotal nuevas alertas: {len(new_entries)}\n")

if __name__ == "__main__":
    main()
