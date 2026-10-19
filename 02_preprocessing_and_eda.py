import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os
import ipaddress

os.makedirs("report_visuals", exist_ok=True)

df = pd.read_parquet("01_tpot_raw_data_30days.parquet")
print(f"Total log count: {df.shape[0]}")


# Honeypot distrubition visual
plt.figure(figsize=(10, 6))
type_counts = df['type'].value_counts()
sns.barplot(x=type_counts.values, y=type_counts.index, hue=type_counts.index, palette="viridis", legend=False)
plt.title("Log distrubition according to honeypot types (raw data)")
plt.xlabel("Log Count")
plt.ylabel("Honeypot / Type")
plt.tight_layout()
plt.savefig("report_visuals/01_honeypot_distrubition.png", dpi=300)
plt.close()

# Most targeted 10 ports
if 'dest_port' in df.columns:
    plt.figure(figsize=(10, 6))
    port_counts = df['dest_port'].value_counts().head(10)
    sns.barplot(x=port_counts.index, y=port_counts.values, hue=port_counts.index, palette="magma", legend=False)
    plt.title("Most targeted 10 ports")
    plt.xlabel("Port (dest_port)")
    plt.ylabel("Attack count")
    plt.tight_layout()
    plt.savefig("report_visuals/02_aimed_ports.png", dpi=300)
    plt.close()


print("\n3. Data preproccesing...")

noise_sensors = ['Suricata', 'P0f']

df_filtered = df[~df['type'].isin(noise_sensors)].copy()

print(f"Remaining log number after filtering: {df_filtered.shape[0]}")
print("\nRemaining logs distribution:")
print(df_filtered['type'].value_counts(dropna=False))


# src_ip validation (flag, don't drop): the pipeline is IPv4-only (07 masks by
# splitting on 4 octets), so anything ipaddress can't parse as IPv4 - None/NaN,
# empty, IPv6, injected payloads like ${jndi:...} - is invalid.
INVALID_SRC_IP = "INVALID"  # no dots -> 07 masks it to "***.***.***.***"


def is_valid_ipv4(value):
    if not isinstance(value, str):
        return False
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


print("\nValidating src_ip (IPv4)...")
df_filtered['src_ip_valid'] = df_filtered['src_ip'].map(is_valid_ipv4)
invalid_mask = ~df_filtered['src_ip_valid']

# Raw value kept only for invalid rows (forensics, e.g. the injected payload);
# for valid rows src_ip already IS the raw value, so it isn't duplicated here.
df_filtered['src_ip_raw'] = df_filtered['src_ip'].where(invalid_mask, None)
df_filtered.loc[invalid_mask, 'src_ip'] = INVALID_SRC_IP

invalid_count = int(invalid_mask.sum())
print(f"Total rows: {len(df_filtered)}")
print(f"Invalid src_ip rows: {invalid_count} (kept, flagged src_ip_valid=False, src_ip='{INVALID_SRC_IP}')")
if invalid_count:
    print("Example invalid raw values:")
    for raw_value in df_filtered.loc[invalid_mask, 'src_ip_raw'].map(repr).value_counts().index[:3]:
        print(f"  - {raw_value[:80]}{'...' if len(raw_value) > 80 else ''}")

columns = [
    '@timestamp', 'type', 'src_ip', 'src_ip_valid', 'src_ip_raw', 'src_port', 'dest_ip', 'dest_port',
    'http.request.method', 'http.request.body.content', 'url', # NGINX / Web
    'payload', 'command', 'input', 'downloads' # Honeytrap, Cowrie, vb.
]

extracted_columns = [col for col in columns if col in df_filtered.columns]
df_clean = df_filtered[extracted_columns].copy()

df_clean.to_parquet("02_tpot_filtered_data.parquet", engine="pyarrow")
print("\n4. Clean data saved -> '02_tpot_filtered_data.parquet'.")