import time
import requests
import threading
from queue import Queue
from datetime import datetime, timezone

# ------------------------------
# CONFIG
# ------------------------------
ELASTIC_URL = "ELASTIC_URL"
ALERT_INDEX = "ALERT_INDEX"
ENRICHER_URL = "ENRICHER_URL"

ELASTIC_USER = "ELASTIC_USER"
ELASTIC_PASS = "ELASTIC_PASS"

# Start from "now" so you don't get flooded with old alerts
last_ts = datetime.now(timezone.utc).isoformat()

# Thread-safe queue for alerts
alert_queue = Queue()

# ------------------------------
# FETCH NEW ALERTS (non-blocking)
# ------------------------------
def fetch_new_alerts():
    global last_ts

    query = {
        "size": 100,
        "sort": [{"@timestamp": "asc"}],
        "query": {
            "range": {
                "@timestamp": {
                    "gt": last_ts
                }
            }
        }
    }

    resp = requests.post(
        f"{ELASTIC_URL}/{ALERT_INDEX}/_search",
        json=query,
        auth=(ELASTIC_USER, ELASTIC_PASS),
        verify=False
    )
    resp.raise_for_status()

    hits = resp.json()["hits"]["hits"]
    if not hits:
        return []

    newest_ts = hits[-1]["_source"]["@timestamp"]
    last_ts = newest_ts

    return [h["_source"] for h in hits]

# ------------------------------
# WORKER THREAD: SEND TO ENRICHER
# ------------------------------
def enricher_worker():
    while True:
        alert = alert_queue.get()
        try:
            print("Sending alert to enricher...")
            r = requests.post(ENRICHER_URL, json=alert, timeout=40)
            r.raise_for_status()
            print("Enrichment complete:", r.text[:200], "...")
        except Exception as e:
            print("Enricher error:", e)
        finally:
            alert_queue.task_done()

# Start the worker thread
threading.Thread(target=enricher_worker, daemon=True).start()

# ------------------------------
# MAIN LOOP (POLLING ONLY)
# ------------------------------
def main():
    print("Poller started. Watching Elastic for new alerts...")
    while True:
        try:
            alerts = fetch_new_alerts()
            for alert in alerts:
                print("Queueing alert for enrichment...")
                alert_queue.put(alert)
        except Exception as e:
            print("Polling error:", e)

        time.sleep(5)

if __name__ == "__main__":
    main()


