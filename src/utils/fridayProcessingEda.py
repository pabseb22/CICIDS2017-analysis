import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from scipy.stats import entropy
from matplotlib.dates import DateFormatter


# ============================================================
# === PATHS ==================================================
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, "..", ".."))

# CSV_FRIDAY_MORNING = os.path.join(
#     PROJECT_ROOT, "pcap_samples", "GeneratedLabelledFlows",
#     "TrafficLabelling", "Friday-WorkingHours-Morning.pcap_ISCX.csv"
# )

CSV_FRIDAY_PORTSCAN = os.path.join(
    PROJECT_ROOT, "pcap_samples", "GeneratedLabelledFlows",
    "TrafficLabelling", "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
)

CSV_FRIDAY_DDOS = os.path.join(
    PROJECT_ROOT, "pcap_samples", "GeneratedLabelledFlows",
    "TrafficLabelling", "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
)

FIGURES_DIR = os.path.join(PROJECT_ROOT, "figures_friday")


# ============================================================
# === ATTACK MAP =============================================
# ============================================================

attack_map = {
    'BENIGN': 'BENIGN',
    'DDoS': 'DDoS',
    'DoS Hulk': 'DoS',
    'DoS GoldenEye': 'DoS',
    'DoS slowloris': 'DoS',
    'DoS Slowhttptest': 'DoS',
    'PortScan': 'Port Scan',
    'FTP-Patator': 'Brute Force',
    'SSH-Patator': 'Brute Force',
    'Bot': 'Bot',
    'Web Attack � Brute Force': 'Web Attack',
    'Web Attack � XSS': 'Web Attack',
    'Web Attack � Sql Injection': 'Web Attack',
    'Infiltration': 'Infiltration',
    'Heartbleed': 'Heartbleed'
}


# ============================================================
# === UTILS ===================================================
# ============================================================

def normalize_filename(name):
    return (
        name.replace(" ", "_")
            .replace("/", "_")
            .replace("\\", "_")
            .replace(":", "_")
            .replace("*", "_")
            .replace("?", "_")
            .replace("<", "_")
            .replace(">", "_")
            .replace("|", "_")
    )


def ensure_folder(folder):
    os.makedirs(folder, exist_ok=True)
    return folder


def save_fig(folder, name):
    name = normalize_filename(name)
    path = os.path.join(folder, f"{name}.png")
    plt.savefig(path, dpi=300, bbox_inches='tight')
    print(f"[+] Figura guardada: {path}")


# ============================================================
# === CARGA DE CSV + FIX DE HORARIO ===========================
# ============================================================

def load_csv(csv_path):
    print(f"\n[Cargando]: {csv_path}")
    df = pd.read_csv(csv_path, low_memory=False)

    df.columns = df.columns.str.strip()
    df.columns = df.columns.str.replace(r"[^\w\s/]", "", regex=True)

    df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce")
    df = df.dropna(subset=["Timestamp"])
    df = df.sort_values("Timestamp")

    # === FIX HORARIO ===
    filename = os.path.basename(csv_path).lower()

    if "morning" in filename:
        print("[+] Dataset de la mañana → sin shift")
    else:
        print("[+] Dataset de la tarde → aplicando +12 horas")
        df["Timestamp"] = df["Timestamp"] + pd.Timedelta(hours=12)

    print("   → Rango temporal corregido:")
    print("     Min:", df["Timestamp"].min())
    print("     Max:", df["Timestamp"].max())

    return df


# ============================================================
# === PREPROCESAMIENTO =======================================
# ============================================================

def preprocess(df):
    df["AttackGroup"] = df["Label"].map(attack_map)
    df["window"] = df["Timestamp"].dt.floor("1s")
    return df


# ============================================================
# === METRICAS POR VENTANA ===================================
# ============================================================

def compute_window_metrics(df):
    return df.groupby("window").agg({
        "Flow ID": "count",
        "Flow Bytes/s": "mean",
        "Flow Packets/s": "mean",
        "Flow Duration": "mean",
        "Source IP": lambda x: x.nunique(),
        "Destination Port": lambda x: x.nunique(),
        "SYN Flag Count": "sum",
        "FIN Flag Count": "sum"
    }).rename(columns={
        "Flow ID": "flows_per_second",
        "Source IP": "unique_src_ips",
        "Destination Port": "unique_dst_ports"
    })


# ============================================================
# === VISUALIZACIONES ========================================
# ============================================================

def flows_plot(df_metrics, folder, title):
    plt.figure(figsize=(14, 4))
    plt.plot(df_metrics.index, df_metrics["flows_per_second"])
    plt.grid(True)
    plt.title(title)
    ax = plt.gca()
    ax.xaxis.set_major_formatter(DateFormatter("%H:%M"))
    plt.xticks(rotation=45, fontsize=9)

    save_fig(folder, "flows_per_second")
    plt.close()


def entropy_plot(df, folder):
    ent = df.groupby("window")["Source IP"].apply(
        lambda x: entropy(x.value_counts())
    )
    plt.figure(figsize=(14, 4))
    plt.plot(ent.index, ent.values, color="purple")
    plt.title("Entropía IP Origen (Botnet / DDoS)")
    plt.grid(True)
    ax = plt.gca()
    ax.xaxis.set_major_formatter(DateFormatter("%H:%M"))
    plt.xticks(rotation=45, fontsize=9)
    save_fig(folder, "entropy")
    plt.close()


def portscan_heatmap(df, folder):
    if "PortScan" not in df["Label"].unique():
        print("[i] No hay PortScan en este CSV.")
        return

    scan = df[df["Label"] == "PortScan"]

    piv = scan.pivot_table(
        index="window",
        columns="Destination Port",
        values="Flow ID",
        aggfunc="count",
        fill_value=0
    )

    # ========= FORMATO BONITO PARA EL EJE Y =========
    piv.index = piv.index.strftime("%H:%M")      # Solo hora:minuto

    plt.figure(figsize=(18, 6))
    ax = sns.heatmap(piv, cmap="YlOrRd")

    plt.title("PortScan Heatmap")

    # Mostrar solo cada 5º label en el eje Y (evita saturación)
    ax.set_yticks(ax.get_yticks()[::5])
    ax.set_yticklabels(ax.get_yticklabels(), rotation=0, fontsize=8)

    # Rotar labels del eje X (puertos)
    ax.set_xticklabels(ax.get_xticklabels(), rotation=90, fontsize=7)

    save_fig(folder, "portscan_heatmap")
    plt.close()


def tcp_flags_plot(df, folder):
    flg = df.groupby("window")[["SYN Flag Count", "ACK Flag Count", "FIN Flag Count"]].sum()

    plt.figure(figsize=(14, 4))
    plt.plot(flg.index, flg["SYN Flag Count"], label="SYN", color="red")
    plt.plot(flg.index, flg["ACK Flag Count"], label="ACK", color="blue")
    plt.plot(flg.index, flg["FIN Flag Count"], label="FIN", color="green")
    plt.title("Evolución Flags TCP")
    plt.legend()
    plt.grid(True)
    ax = plt.gca()
    ax.xaxis.set_major_formatter(DateFormatter("%H:%M"))
    plt.xticks(rotation=45, fontsize=9)

    save_fig(folder, "tcp_flags")
    plt.close()


def scatter_plot(df, folder, x, y):
    plt.figure(figsize=(10, 6))
    for attack in df["AttackGroup"].unique():
        if attack == "BENIGN":
            continue
        subset = df[df["AttackGroup"] == attack]
        plt.scatter(subset[x], subset[y], s=10, alpha=0.4, label=attack)

    plt.xlabel(x)
    plt.ylabel(y)
    plt.title(f"Scatter {x} vs {y}")
    plt.legend()
    plt.grid(True)
    save_fig(folder, f"scatter_{x}_{y}")
    plt.close()


# ============================================================
# === PIPELINES ESPECÍFICOS ==================================
# ============================================================

# def process_friday_morning():
#     folder = ensure_folder(os.path.join(FIGURES_DIR, "morning_botnet"))
#     df = preprocess(load_csv(CSV_FRIDAY_MORNING))
#     metrics = compute_window_metrics(df)

#     print("\n[+] Analizando Botnet (10:02–11:02)")
#     flows_plot(metrics, folder, "Flows/s - Botnet ARES")
#     entropy_plot(df, folder)
#     scatter_plot(df, folder, "Flow Packets/s", "Flow Duration")
#     return df, metrics


def process_friday_portscan():
    folder = ensure_folder(os.path.join(FIGURES_DIR, "portscan"))
    df = preprocess(load_csv(CSV_FRIDAY_PORTSCAN))
    metrics = compute_window_metrics(df)

    print("\n[+] Analizando PortScan")
    flows_plot(metrics, folder, "Flows/s - PortScan")
    tcp_flags_plot(df, folder)
    portscan_heatmap(df, folder)
    scatter_plot(df, folder, "Flow Packets/s", "Flow Duration")
    return df, metrics


def process_friday_ddos():
    folder = ensure_folder(os.path.join(FIGURES_DIR, "ddos_loit"))
    df = preprocess(load_csv(CSV_FRIDAY_DDOS))
    metrics = compute_window_metrics(df)

    print("\n[+] Analizando DDoS LOIT (15:56–16:16)")
    flows_plot(metrics, folder, "Flows/s - DDoS LOIT")
    entropy_plot(df, folder)
    tcp_flags_plot(df, folder)
    scatter_plot(df, folder, "Flow Bytes/s", "Flow Packets/s")
    return df, metrics


# ============================================================
# === RUN =====================================================
# ============================================================

if __name__ == "__main__":
    # df_morning, m_morning = process_friday_morning()
    df_ps, m_ps = process_friday_portscan()
    df_ddos, m_ddos = process_friday_ddos()

    print("\n[✔] Todos los análisis del viernes generados.")
