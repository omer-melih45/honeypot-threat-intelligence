import pandas as pd
import re
import os

# ---------------------------------------------------------
# KVKK (Law No. 6698) & Law No. 5651 Compliance Pipeline
# ---------------------------------------------------------

def mask_ip_address(ip_string):
    # Hides the last two parts of an IP address.
    # Example: 185.67.33.193 -> 185.67.***.***
    if pd.isna(ip_string):
        return ip_string
    
    parts = str(ip_string).split('.')
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.***.***"
    return "***.***.***.***"

def anonymize_report_content(text_content):
    # Finds every IP address in a text and masks it.
    ipv4_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    
    def replace_match(match):
        return mask_ip_address(match.group(0))
        
    return ipv4_pattern.sub(replace_match, text_content)

def enforce_dataset_compliance(input_filepath, output_filepath):
    # Loads the dataset, masks the IP columns and saves a safe copy.
    print(f"Loading dataset for compliance check: {input_filepath}")
    df = pd.read_parquet(input_filepath)
    
    if 'src_ip' in df.columns:
        df['src_ip'] = df['src_ip'].apply(mask_ip_address)
        print("Source IP column successfully anonymized.")

    # src_ip_raw (from 02) keeps the original value of invalid src_ip rows and can
    # embed an IPv4 inside a payload string. Only non-null values are masked
    # (valid rows have None there); older parquets without the column still work.
    if 'src_ip_raw' in df.columns:
        has_raw = df['src_ip_raw'].notna()
        df.loc[has_raw, 'src_ip_raw'] = df.loc[has_raw, 'src_ip_raw'].astype(str).apply(anonymize_report_content)
        print("Raw source IP column successfully anonymized.")

    df.to_parquet(output_filepath, index=False)
    print(f"Compliant dataset saved to: {output_filepath}")

def enforce_reports_compliance(directory_path):
    # Goes through all AI reports and masks the IP addresses in them.
    print(f"\nScanning reports directory: {directory_path}")
    if not os.path.exists(directory_path):
        print("Directory not found. Skipping report compliance.")
        return

    processed_count = 0
    for filename in os.listdir(directory_path):
        if filename.endswith(".txt"):
            file_path = os.path.join(directory_path, filename)
            
            with open(file_path, 'r', encoding='utf-8') as file:
                raw_data = file.read()
                
            compliant_data = anonymize_report_content(raw_data)
            
            with open(file_path, 'w', encoding='utf-8') as file:
                file.write(compliant_data)
                
            print(f"Compliance enforced on: {filename}")
            processed_count += 1
            
    print(f"Total reports secured: {processed_count}")

if __name__ == "__main__":
    DATASET_INPUT = "04_tpot_30days_final_labeled.parquet"
    DATASET_OUTPUT = "FINAL_tpot_30days_kvkk_compliant.parquet"
    REPORTS_DIR = "ai_reports"
    
    print("==================================================")
    print("INITIATING KVKK COMPLIANCE & DATA ANONYMIZATION")
    print("==================================================\n")
    
    enforce_dataset_compliance(DATASET_INPUT, DATASET_OUTPUT)
    enforce_reports_compliance(REPORTS_DIR)
    
    print("\n==================================================")
    print("COMPLIANCE PIPELINE EXECUTED SUCCESSFULLY")
    print("==================================================")