import pandas as pd
import re
import base64
import urllib.parse

df = pd.read_parquet("02_tpot_filtered_data.parquet")

# If there is no payload or downloads column
if 'payload' not in df.columns:
    df['payload'] = ""
if 'downloads' not in df.columns:
    df['downloads'] = ""

print("Starting rule based labeling...")

def detect_hidden_malware(text):
    commands = ['wget', 'curl', 'powershell', 'chmod+x', 'certutil', 'bitsadmin']
    
    if not isinstance(text, str) or text == "":
        return False

    decoded_url_text = urllib.parse.unquote(text).lower()
    
    stripped_text = decoded_url_text.replace(" ", "")

    if any(cmd in stripped_text for cmd in commands):
        return True

    b64_pattern = r'(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
    potential_b64 = re.findall(b64_pattern, text)

    for b64_str in potential_b64:
        try:
            decoded = base64.b64decode(b64_str).decode('utf-8', errors='ignore').lower().replace(" ", "")
            if any(cmd in decoded for cmd in commands):
                return True
            decoded_utf16 = base64.b64decode(b64_str).decode('utf-16-le', errors='ignore').lower().replace(" ", "")
            if any(cmd in decoded_utf16 for cmd in commands):
                return True
        except:
            continue
            
    return False

def categorize_attack(row):
    payload = str(row.get('payload', ''))
    url_str = str(row.get('url', ''))
    combined_text = payload + " " + url_str
    
    downloads = str(row.get('downloads', '')).lower().strip()
    dest_port = row.get('dest_port', 0)
    sensor_type = str(row.get('type', ''))

    has_download = downloads not in ["", "[]", "{}", "nan", "none", "null", "<na>"]
    
    if detect_hidden_malware(combined_text) or has_download:
        return "Malware_Dropper"

    erp_keywords = ['sa', 'mssql', 'dba', 'admin', 'logo', 'mikro', 'nebim', 'zirve']
    if dest_port in [1433, 3306, 5432] or any(kw in payload.lower() for kw in erp_keywords):
        return "Database_ERP_BruteForce"

    web_keywords = ['select ', 'union ', 'script>', '../', '%2e%2e%2f', 'cmd.exe', '/bin/sh']
    if sensor_type == 'NGINX' or any(kw in payload.lower() for kw in web_keywords) or any(kw in url_str.lower() for kw in web_keywords):
        return "Web_Exploit_Attempt"
    
    if sensor_type == 'Fatt':
        return "Encrypted_Traffic_Profile"

    return "Uncategorized"

df['Attack_Type'] = df.apply(categorize_attack, axis=1)


print("\n3. Results::")
attack_counts = df['Attack_Type'].value_counts()
print(attack_counts)

# Filtering uncategorized for ml step
df_uncategorized = df[df['Attack_Type'] == "Uncategorized"]
print(f"\nLog number that will be sent to ml step: {len(df_uncategorized)}")

# Saving labeled data
df.to_parquet("03_tpot_labeled_data.parquet", engine="pyarrow")
print("\n4. Data saved -> '03_tpot_labeled_data.parquet'.")