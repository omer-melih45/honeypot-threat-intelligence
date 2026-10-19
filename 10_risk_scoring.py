import hashlib
import os
import time

import pandas as pd
import requests
from dotenv import load_dotenv

load_dotenv()


# Risk Score (0-100) per attacker IP. Combines:
#   - AbuseIPDB reputation score (external, 50%)
#   - VirusTotal detection count on the IP's payload (external, 30%)
#   - ML anomaly flag from 04_ml_anomaly.py (internal, 20%)
#
# A signal that can't be obtained (missing API key, request failure,
# no payload to check, or a payload hash VirusTotal has never seen) is
# left out of the average instead of being treated as "0 risk" - the
# remaining weights are renormalized so missing data never silently
# makes an IP look clean. Weights below are tunable.


ABUSE_WEIGHT = 0.5
VT_WEIGHT = 0.3
ML_FLAG_WEIGHT = 0.2


def check_abuseipdb(ip_address):
    # Gets the AbuseIPDB score (0-100) for an IP. Returns None if it fails.
    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if not api_key:
        return None

    url = "https://api.abuseipdb.com/api/v2/check"
    querystring = {"ipAddress": ip_address, "maxAgeInDays": "90"}
    headers = {"Accept": "application/json", "Key": api_key}

    try:
        response = requests.get(url, headers=headers, params=querystring)
        if response.status_code == 200:
            return float(response.json()["data"]["abuseConfidenceScore"])
    except Exception as e:
        print(f"  AbuseIPDB lookup failed for {ip_address}: {e}")
    return None


def check_virustotal(payload_text):
    # Turns the VirusTotal detection count into a 0-100 score. Returns None if unknown.
    api_key = os.environ.get("VT_API_KEY")
    if not api_key or not payload_text:
        return None

    payload_hash = hashlib.sha256(str(payload_text).encode("utf-8")).hexdigest()
    url = f"https://www.virustotal.com/api/v3/files/{payload_hash}"
    headers = {"accept": "application/json", "x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers)
        time.sleep(15)  # stay under VirusTotal's public 4 requests/minute limit
        if response.status_code == 200:
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
            detection_count = stats["malicious"]
            total_engines = sum(stats.values())
            return (detection_count / total_engines) * 100 if total_engines else None
        # 404 = hash never seen before -> no verdict either way, not evidence of safety
    except Exception as e:
        print(f"  VirusTotal lookup failed: {e}")
    return None


def combine_scores(abuse_score, vt_score, ml_anomaly_score):
    components = [
        (ABUSE_WEIGHT, abuse_score),
        (VT_WEIGHT, vt_score),
        (ML_FLAG_WEIGHT, ml_anomaly_score),
    ]
    available = [(w, s) for w, s in components if s is not None]
    total_weight = sum(w for w, _ in available)
    if total_weight == 0:
        return 0.0
    weighted_sum = sum(w * s for w, s in available)
    return round(weighted_sum / total_weight, 1)


if __name__ == "__main__":
    print("1. Loading labeled data...")
    df = pd.read_parquet("04_tpot_30days_final_labeled.parquet")

    print("2. Aggregating per-IP ML anomaly flag + payload sample...")
    is_anomaly = df.groupby("src_ip")["Attack_Type"].apply(lambda s: (s == "ML_Detected_Anomaly").any())

    # Longest payload per IP = most information-dense sample to check against VirusTotal
    df["payload_length"] = df["payload"].apply(lambda x: len(str(x)) if pd.notnull(x) else 0)
    longest_payload = (
        df[df["payload_length"] > 0]
        .sort_values("payload_length", ascending=False)
        .groupby("src_ip")["payload"]
        .first()
    )

    unique_ips = df["src_ip"].dropna().unique()
    print(f"3. Scoring {len(unique_ips)} unique attacker IPs via AbuseIPDB + VirusTotal...")

    rows = []
    for idx, src_ip in enumerate(unique_ips, start=1):
        abuse_score = check_abuseipdb(src_ip)
        vt_score = check_virustotal(longest_payload.get(src_ip))
        is_ml_anomaly = bool(is_anomaly.get(src_ip, False))
        ml_anomaly_score = 100.0 if is_ml_anomaly else 0.0

        risk_score = combine_scores(abuse_score, vt_score, ml_anomaly_score)

        rows.append({
            "src_ip": src_ip,
            "Risk_Score": risk_score,
            "abuse_score": abuse_score,
            "virustotal_score": vt_score,
            "is_ml_anomaly": is_ml_anomaly,
        })

        if idx % 50 == 0 or idx == len(unique_ips):
            print(f"   ...{idx}/{len(unique_ips)} IPs scored")

        time.sleep(0.3)  # stay well under AbuseIPDB's rate limit

    risk_df = pd.DataFrame(rows).sort_values("Risk_Score", ascending=False)

    print("\n--- Top 10 highest-risk IPs ---")
    print(risk_df.head(10).to_string(index=False))

    risk_df.to_parquet("10_ip_risk_scores.parquet", index=False)
    print(f"\n4. Risk scores saved -> '10_ip_risk_scores.parquet' ({len(risk_df)} IPs)")
