import pandas as pd
import numpy as np
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
import seaborn as sns
import os

df = pd.read_parquet("03_tpot_labeled_data.parquet")

# Only getting uncategorized data
df_ml = df[df['Attack_Type'] == 'Uncategorized'].copy()
print(f"İşlenecek Log Sayısı: {len(df_ml)}")

# Time based sorting
df_ml['@timestamp'] = pd.to_datetime(df_ml['@timestamp'])
df_ml = df_ml.sort_values(by=['src_ip', '@timestamp'])

print("\n2. Feature Engineering...")

# Feature 1: payload lenght
df_ml['payload_length'] = df_ml['payload'].apply(lambda x: len(str(x)) if pd.notnull(x) else 0)

# Feature 2: time diff
df_ml['time_diff'] = df_ml.groupby('src_ip')['@timestamp'].diff().dt.total_seconds().fillna(0)

# Feature 3: Aimed port
df_ml['dest_port'] = df_ml['dest_port'].fillna(0)

features = ['payload_length', 'time_diff', 'dest_port']

# 3. Standardization
scaler = StandardScaler()
X_scaled = scaler.fit_transform(df_ml[features])

print("3. K-Means clustering (K=3)...")
#1) Noise 2) Mid scans 3) Anomalies
kmeans = KMeans(n_clusters=3, random_state=42, n_init=10)
df_ml['Cluster'] = kmeans.fit_predict(X_scaled)

print("\n--- Cluster analyze ---")
cluster_stats = df_ml.groupby('Cluster')[features].mean()
cluster_counts = df_ml['Cluster'].value_counts()
print(pd.concat([cluster_stats, cluster_counts.rename('Count')], axis=1))

anomaly_cluster = cluster_counts.idxmin()
print(f"\nPrediction: Cluster {anomaly_cluster} looks like an anomaly")

os.makedirs("report_visuals", exist_ok=True)
plt.figure(figsize=(10, 6))
sns.scatterplot(
    data=df_ml, 
    x='dest_port', 
    y='payload_length', 
    hue='Cluster', 
    palette='viridis', 
    alpha=0.6
)
plt.title("K-Means Clustering")
plt.savefig("report_visuals/03_kmeans_clusters.png", dpi=300)
plt.close()

df_ml.loc[df_ml['Cluster'] == anomaly_cluster, 'Attack_Type'] = 'ML_Detected_Anomaly'

df.update(df_ml[['Attack_Type']])

df.to_parquet("04_tpot_30days_final_labeled.parquet", engine="pyarrow")
print("\n4. Data saved -> '04_tpot_30days_final_labeled.parquet'")