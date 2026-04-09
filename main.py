import json
import os
from modules.feeds import fetch_all_feeds
from modules.notifier import send_telegram
from database import init_db, insert_alert

HISTORY_FILE = "/home/ubuntu/cyber-threat-monitor/data/history.json"

def load_history():
    if not os.path.exists(HISTORY_FILE):
        print("📁 Archivo no existe, creando...")
        return []
    with open(HISTORY_FILE, "r") as f:
        try:
            data = json.load(f)
            print(f"📂 Cargadas {len(data)} noticias")
            return data
        except Exception as e:
            print(f"❌ Error cargando: {e}")
            return []

def save_history(history):
    try:
        with open(HISTORY_FILE, "w") as f:
            json.dump(history, f, indent=4)
        print(f"💾 Guardadas {len(history)} noticias en {HISTORY_FILE}")
    except Exception as e:
        print(f"❌ Error guardando: {e}")

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
    print("="*50)
    print("INICIANDO MONITOR DE SEGURIDAD")
    print("="*50)
    
    history = load_history()
    existing_links = [item["link"] for item in history]
    
    print(f"📊 Historial: {len(existing_links)} noticias previas")
    
    new_entries = fetch_all_feeds(existing_links)
    print(f"📡 Nuevas noticias detectadas: {len(new_entries)}")
    
    sent_count = 0
    for entry in new_entries:
        if entry["severity"] not in ["🔴 CRITICAL", "🟠 HIGH"]:
            print(f"⏭️ Saltando {entry['title']} ({entry['severity']})")
            continue
        
        message = format_alert(entry)
        print(f"📤 Enviando: {entry['title']}")
        send_telegram(message)
        insert_alert(entry)
        
        history.append({"link": entry["link"], "title": entry["title"]})
        sent_count += 1
    
    save_history(history)
    
    print(f"\n✅ Enviadas: {sent_count} alertas")
    print(f"📊 Total en historial: {len(history)} noticias")
    print("="*50)

if __name__ == "__main__":
    main()
