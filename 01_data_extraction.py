import pandas as pd
import requests
import json
import gc
import os
import sys
from dotenv import load_dotenv

load_dotenv()

# Elasticsearch location/credentials from .env (same settings status_check.py uses).
# `or` (not a .get default) so empty placeholders copied from .env.example fall back too.
host = (os.environ.get("ES_HOST") or "http://localhost:9200").rstrip("/")
index = os.environ.get("ES_INDEX") or "logstash-*"
es_user = os.environ.get("ES_USER")
es_password = os.environ.get("ES_PASSWORD")
auth = (es_user, es_password) if es_user and es_password else None

headers = {"Content-Type": "application/json"}
day_count = 30
max_log_per_day = 1000000

# Fail fast with a clear message instead of 30 per-day connection errors
try:
    probe = requests.get(host, headers=headers, auth=auth, timeout=10)
except requests.exceptions.RequestException:
    print(f"Could not reach Elasticsearch: {host}. Check ES_HOST in .env "
          "(inside Docker use http://host.docker.internal:9200).")
    print("For a demo run without Elasticsearch: python generate_demo_data.py, then streamlit run dashboard.py")
    sys.exit(1)
if probe.status_code in (401, 403):
    print(f"Elasticsearch at {host} rejected the request (HTTP {probe.status_code}). "
          "Check ES_USER / ES_PASSWORD in .env.")
    sys.exit(1)

#only required columns (for system efficiency)
columns = ['@timestamp', 'type', 'src_ip', 'src_port', 'dest_ip', 'dest_port', 'payload', 'downloads', 'http.request.method', 'url']

all_days_data = []

print(f"{day_count} days data extracting...\n")

for i in range(day_count, 0, -1):
    init = f"now-{i}d"
    finish = f"now-{i-1}d" if i > 1 else "now"
    print(f"--- day {day_count - i + 1} is processing ({init} -> {finish}) ---")
    
    search_url = f"{host}/{index}/_search?scroll=2m"
    query = {
        "size": 10000,
        "query": {"range": {"@timestamp": {"gte": init, "lte": finish}}}
    }
    
    day_data = []
    try:
        response = requests.post(search_url, headers=headers, data=json.dumps(query), auth=auth)
        if response.status_code != 200:
            print(f"Elasticsearch returned HTTP {response.status_code} for index '{index}'.")
        if response.status_code == 200:
            data = response.json()
            scroll_id = data.get("_scroll_id")
            hits = data.get("hits", {}).get("hits", [])

            while hits and len(day_data) < max_log_per_day:
                day_data.extend([hit["_source"] for hit in hits])
                scroll_url = f"{host}/_search/scroll"
                scroll_query = {"scroll": "2m", "scroll_id": scroll_id}
                response = requests.post(scroll_url, headers=headers, data=json.dumps(scroll_query), auth=auth)
                data = response.json()
                scroll_id = data.get("_scroll_id")
                hits = data.get("hits", {}).get("hits", [])
    except Exception as e:
        print(f"Error: {e}")

    if not day_data:
        print("No data, pass\n")
        continue

    df_day = pd.DataFrame(day_data)
    
    for col in df_day.columns:
        if df_day[col].dropna().apply(lambda x: isinstance(x, (dict, list))).any():
            df_day[col] = df_day[col].astype(str)
            
    columns_extracted = [col for col in columns if col in df_day.columns]
    df_day = df_day[columns_extracted]
    
    all_days_data.append(df_day)
    print(f"Extraction succesful. (Raw: {len(df_day)})\n")

    #cleaning ram
    del day_data
    del df_day
    gc.collect()

if all_days_data:
    print("All days combining. Saving to parquet")
    df_final = pd.concat(all_days_data, ignore_index=True)
    df_final.to_parquet("01_tpot_raw_data_30days.parquet", engine="pyarrow")
    print("SUCCESSFULL: Data saved -> '01_tpot_raw_data_30days.parquet'.")