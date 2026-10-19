import pandas as pd
import os
from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage
from dotenv import load_dotenv


load_dotenv()


# gpt-oss-20b is a reasoning model: reasoning tokens count against max_tokens too,
# so the limit is set generously to keep the full report from being cut off.
llm = ChatGroq(model_name="openai/gpt-oss-20b", temperature=0.3, max_tokens=8192)

system_prompt = """You are an elite Chief Information Security Officer (CISO) and Lead Threat Intelligence Analyst.
You are presented with aggregated 30-day statistics from a multi-vector honeypot network deployed in Turkey.

Your task is to write a high-level, professional Executive Monthly Threat Report.
Do NOT just repeat the numbers. Analyze WHAT these numbers mean for the business.

REPORT STRUCTURE:
1. EXECUTIVE OVERVIEW: A high-level summary of the month's threat landscape.
2. THREAT LANDSCAPE ANALYSIS: Interpret the attack types. Why is ERP BruteForce so high? What does the Uncategorized volume suggest?
3. TARGETING TRENDS: Analyze the top targeted ports and what attackers are looking for.
4. STRATEGIC RECOMMENDATIONS: 3 actionable infrastructure recommendations for the IT department based on these trends.

Tone: Authoritative, strategic, corporate, and highly analytical.

Do NOT add any signature, sign-off, "Prepared by" line, author name, title, placeholder (e.g. [Name]), or date anywhere in the report. Do not invent metadata of any kind. End the report with the final section's actual content (the strategic recommendations).
"""


def build_stats_context(df):
    # Turns the 30-day data into a short summary text for the LLM.
    total_logs = len(df)
    attack_dist = df['Attack_Type'].value_counts().to_string()

    df_ports = df[df['dest_port'] > 0]
    top_ports = df_ports['dest_port'].value_counts().head(5).to_string()

    top_sensors = df['type'].value_counts().head(3).to_string()

    return f"""
--- 30-DAY THREAT INTELLIGENCE STATISTICS ---
Total Logs Analyzed: {total_logs}

Attack Type Distribution:
{attack_dist}

Top 5 Targeted Ports:
{top_ports}

Top 3 Sensors Triggered:
{top_sensors}
"""


def generate_executive_report_with_finish_reason(stats_context):
    # Asks the LLM for the CISO report. Returns (report_text, finish_reason).
    # finish_reason "stop" = the report is complete,
    # "length" = it was cut off because it hit the token limit.
    response = llm.invoke([
        SystemMessage(content=system_prompt),
        HumanMessage(content=stats_context)
    ])
    return response.content, response.response_metadata.get("finish_reason")


def generate_executive_report(stats_context):
    # Same as above, but only returns the report text.
    report, _ = generate_executive_report_with_finish_reason(stats_context)
    return report


if __name__ == "__main__":
    df = pd.read_parquet("04_tpot_30days_final_labeled.parquet")

    stats_context = build_stats_context(df)
    report = generate_executive_report(stats_context)

    print("="*60)
    print("MONTHLY EXECUTIVE THREAT REPORT")
    print("="*60)
    print(report)

    # Raporu dosyaya kaydetme
    os.makedirs("ai_reports", exist_ok=True)
    with open("ai_reports/monthly_executive_report.txt", "w", encoding="utf-8") as f:
        f.write(report)

    print("\nReport saved -> 'ai_reports/monthly_executive_report.txt'")
