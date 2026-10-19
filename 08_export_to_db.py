import pandas as pd
import sqlite3
import os

conn = sqlite3.connect("threat_intel.db")
cursor = conn.cursor()

df = pd.read_parquet("FINAL_tpot_30days_kvkk_compliant.parquet")

df.to_sql("network_threat_logs", conn, if_exists="replace", index=False)
print(f"{len(df)} logs saved to table: 'network_threat_logs'.")


print("\n3. Table for AI reports")
cursor.execute('''
    CREATE TABLE IF NOT EXISTS ai_intelligence_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        report_type TEXT,
        report_content TEXT,
        creation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
''')

reports_dir = "ai_reports"
if os.path.exists(reports_dir):
    for filename in os.listdir(reports_dir):
        if filename.endswith(".txt"):
            filepath = os.path.join(reports_dir, filename)
            with open(filepath, "r", encoding="utf-8") as file:
                content = file.read()
                
            report_type = "Executive CISO Report" if "monthly" in filename else "Anomaly Technical Report"
            
            cursor.execute('''
                INSERT INTO ai_intelligence_reports (report_type, report_content)
                VALUES (?, ?)
            ''', (report_type, content))
    
    print("AI reports saved: 'ai_intelligence_reports'")

conn.commit()
conn.close()

print("SUCCESFUL")