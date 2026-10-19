import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os

sns.set_theme(style="whitegrid", palette="muted")

print("1. Initializing visualization pipeline...")
output_dir = "report_visuals"
os.makedirs(output_dir, exist_ok=True)

print("2. Loading labeled dataset...")
df = pd.read_parquet("04_tpot_30days_final_labeled.parquet")


print("3. Generating Attack Type Distribution chart...")
plt.figure(figsize=(10, 6))

# Get the top 5 attack types
attack_counts = df['Attack_Type'].value_counts().head(5)

# Create a horizontal bar plot
sns.barplot(x=attack_counts.values, y=attack_counts.index, hue=attack_counts.index, palette="viridis", legend=False)

plt.title("Top 5 Attack Types Detected by Rule Engine", fontsize=14, fontweight='bold')
plt.xlabel("Number of Logs", fontsize=12)
plt.ylabel("Attack Type Classification", fontsize=12)
plt.tight_layout()

plt.savefig(f"{output_dir}/04_attack_type_distribution.png", dpi=300)
plt.close()

print(f"\nSUCCESS: All report visualizations have been generated and saved to the '{output_dir}' directory.")