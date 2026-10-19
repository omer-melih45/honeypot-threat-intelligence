import pandas as pd
import os
from langchain_core.tools import tool
from langchain_groq import ChatGroq
from langgraph.prebuilt import create_react_agent
from langchain_core.messages import SystemMessage, HumanMessage
import requests
import hashlib
from dotenv import load_dotenv
load_dotenv()

@tool
def check_abuseipdb(ip_address: str) -> str:
    """Useful for checking the reputation and malicious history of an IP address."""
    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if not api_key:
        return "AbuseIPDB API key is missing."

    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {'ipAddress': ip_address, 'maxAgeInDays': '90'}
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }
    
    try:
        response = requests.get(url, headers=headers, params=querystring)
        if response.status_code == 200:
            data = response.json()['data']
            score = data['abuseConfidenceScore']
            reports = data['totalReports']
            return f"AbuseIPDB Result for {ip_address}: Abuse Confidence Score is {score}%. This IP has been reported {reports} times in the last 90 days."
        return f"AbuseIPDB returned status code {response.status_code}."
    except Exception as e:
        return f"Failed to connect to AbuseIPDB: {str(e)}"

@tool
def analyze_payload_hash(payload_text: str) -> str:
    """Useful for checking if a specific payload matches known malware signatures on VirusTotal."""
    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        return "VirusTotal API key is missing."

    payload_hash = hashlib.sha256(payload_text.encode('utf-8')).hexdigest()
    url = f"https://www.virustotal.com/api/v3/files/{payload_hash}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            malicious_count = stats['malicious']
            return f"VirusTotal Result: {malicious_count} security vendors flagged this exact payload hash as malicious."
        elif response.status_code == 404:
            return "VirusTotal Result: This specific payload hash has never been seen by VirusTotal before (Possible Zero-Day or unique attacker script)."
        return f"VirusTotal returned status code {response.status_code}."
    except Exception as e:
        return f"Failed to connect to VirusTotal: {str(e)}"

llm = ChatGroq(model_name="openai/gpt-oss-20b", temperature=0.2, max_tokens=4096)
tools = [check_abuseipdb, analyze_payload_hash]

system_prompt = """You are an elite Autonomous Threat Intelligence Analyst working in a SOC.
Your task is to analyze network anomalies detected by unsupervised machine learning models on a multi-vector honeypot network (T-Pot).

When you receive a log, you must:
1. Examine the Source IP, Target Port, and Payload.
2. Use your tools to enrich the data (IP reputation, CVE identification).
3. Determine the attacker's objective (e.g., Remote Code Execution, Data Exfiltration, Botnet Propagation).
4. Deobfuscate or explain any malicious commands within the payload.
5. Generate a formal, structured Threat Intelligence Report.

REPORT STRUCTURE:
- EXECUTIVE SUMMARY: A brief overview of the attack.
- TACTICS, TECHNIQUES & PROCEDURES (TTPs): MITRE ATT&CK alignment.
- TECHNICAL ANALYSIS: Deep dive into the payload and ports.
- INTELLIGENCE ENRICHMENT: Findings from external tools.
- MITIGATION STRATEGIES: Actionable defense recommendations.

Do not invent API responses; rely on the information provided by your tools and your internal knowledge of cybersecurity. Maintain a highly technical, objective, and professional tone.
"""

agent_executor = create_react_agent(llm, tools)


def generate_threat_report(context_text: str) -> str:
    # Runs the AI agent on the given text and returns the report.
    # The dashboard also uses this function. Only this call talks to the API.
    response = agent_executor.invoke({
        "messages": [
            SystemMessage(content=system_prompt),
            HumanMessage(content=context_text)
        ]
    })
    return response["messages"][-1].content


if __name__ == "__main__":
    print("1. Loading Labeled Parquet Data...")
    df = pd.read_parquet("04_tpot_30days_final_labeled.parquet")

    anomalies = df[df['Attack_Type'] == 'ML_Detected_Anomaly']
    print(f"Detected {len(anomalies)} critical anomalies for AI analysis.\n")

    if not anomalies.empty:
        target_anomaly = anomalies.iloc[0]

        attack_context = f"""
        Please analyze the following anomalous network log:
        - Timestamp: {target_anomaly['@timestamp']}
        - Source IP: {target_anomaly['src_ip']}
        - Target Port: {target_anomaly['dest_port']}
        - Sensor Type: {target_anomaly['type']}
        - Payload Length: {len(str(target_anomaly['payload']))} characters
        - Raw Payload: {target_anomaly['payload']}
        """

        print("2. Starting Autonomous AI Analysis via Groq...\n")

        report = generate_threat_report(attack_context)

        print("\n" + "="*50)
        print("FINAL THREAT INTELLIGENCE REPORT")
        print("="*50)
        print(report)

        os.makedirs("ai_reports", exist_ok=True)
        with open("ai_reports/anomaly_report_01.txt", "w", encoding="utf-8") as f:
            f.write(report)
    else:
        print("No anomalies found to analyze.")