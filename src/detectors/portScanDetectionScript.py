import time
import os
import sys
import pandas as pd
import matplotlib.pyplot as plt
from scipy.stats import entropy


# ===========================
# CONFIG RUTAS
# ===========================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, "..", ".."))
sys.path.append(os.path.join(PROJECT_ROOT, "src"))

CSV_PATH = os.path.join(
    PROJECT_ROOT, "pcap_samples", "GeneratedLabelledFlows",
    "TrafficLabelling", "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
)

WINDOW_SECONDS = 1
REALTIME_DELAY = 0.10
GAUSS_K = 4     # μ + kσ
IQR_K = 1.5     # regla de Tukey
PERCENTIL = 0.99


# ===========================
# LOAD CSV (limpio)
# ===========================
def load_csv(csv_path):
    print(f"\n[Cargando]: {csv_path}")
    df = pd.read_csv(csv_path, low_memory=False)

    df.columns = df.columns.str.strip()
    df.columns = df.columns.str.replace(r"[^\w\s/]", "", regex=True)

    print("\n[Columnas detectadas]:")
    print(df.columns.tolist())

    df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce")
    df = df.dropna(subset=["Timestamp"])
    df = df.sort_values("Timestamp")

    filename = os.path.basename(csv_path).lower()
    if "morning" in filename:
        print("[+] Dataset morning → sin shift")
    else:
        print("[+] Dataset afternoon → +12 horas")
        df["Timestamp"] = df["Timestamp"] + pd.Timedelta(hours=12)

    return df


# ===========================
# FEATURE: METRICAS PORTSCAN
# ===========================
def compute_window_metrics(df):
    df["window"] = df["Timestamp"].dt.floor("1s")

    return df.groupby("window").agg({
        "Flow ID": "count",
        "Destination Port": lambda x: x.nunique(),
        "Source IP": lambda x: x.nunique(),
        "SYN Flag Count": "sum",
    }).rename(columns={
        "Flow ID": "flows_per_second",
        "Destination Port": "unique_dst_ports",
        "Source IP": "unique_src_ips",
        "SYN Flag Count": "syn_count",
    })


# ===========================
# UMBRALES VARIOS
# ===========================
def compute_thresholds(benign_series):
    thresholds = {}

    # Gauss μ + kσ
    mu = benign_series.mean()
    sigma = benign_series.std()
    thresholds["Gauss"] = mu + GAUSS_K * sigma

    # IQR Q3 + 1.5*IQR
    Q1 = benign_series.quantile(0.25)
    Q3 = benign_series.quantile(0.75)
    IQR = Q3 - Q1
    thresholds["IQR"] = Q3 + IQR_K * IQR

    # Percentil
    thresholds["Percentil"] = benign_series.quantile(PERCENTIL)

    return thresholds


# ===========================
# COMPARACIÓN DE UMBRALES
# ===========================
def plot_portscan_comparison(metrics, thresholds, metric_name="unique_dst_ports"):
    series = metrics[metric_name]

    plt.figure(figsize=(14, 5))
    plt.plot(series.index, series.values, label=metric_name, linewidth=1.6)

    for name, thr in thresholds.items():
        plt.axhline(thr, linestyle="--", linewidth=1.4, label=f"{name} = {thr:.2f}")

    plt.title(f"Comparación de umbrales — PortScan ({metric_name})")
    plt.xlabel("Tiempo")
    plt.ylabel(metric_name)
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    plt.show()


# ===========================
# REAL-TIME PLOT (animación)
# ===========================
def realtime_plot(metrics, threshold, metric_name, delay=0.1):
    plt.ion()
    fig, ax = plt.subplots(figsize=(14, 5))

    xs, ys = [], []
    alert_x, alert_y = [], []

    (line,) = ax.plot([], [], label=metric_name, linewidth=1.4)
    (alert_scatter,) = ax.plot([], [], "ro", label="ALERTA")
    ax.axhline(threshold, ls="--", color="orange", label="Threshold")

    ax.set_title(f"PortScan — Real-time detection ({metric_name})")
    ax.set_xlabel("Tiempo")
    ax.set_ylabel(metric_name)
    ax.grid(True)
    ax.legend()

    for idx, row in metrics.iterrows():
        val = row[metric_name]

        xs.append(row.name)
        ys.append(val)

        line.set_xdata(xs)
        line.set_ydata(ys)

        ax.set_xlim(min(xs), max(xs))
        ax.set_ylim(0, max(ys) * 1.2)

        if val > threshold:
            alert_x.append(row.name)
            alert_y.append(val)
            alert_scatter.set_xdata(alert_x)
            alert_scatter.set_ydata(alert_y)

        plt.pause(0.01)
        time.sleep(delay)

    plt.ioff()
    plt.show()


# ===========================
# RUN
# ===========================
print("[Cargando dataset PortScan...]")
df = load_csv(CSV_PATH)

metrics = compute_window_metrics(df)

# baseline SOLO BENIGN
benign = df[df["Label"] == "BENIGN"]
benign_metrics = compute_window_metrics(benign)

# LA MEJOR MÉTRICA PARA PORTSCAN
metric_name = "unique_dst_ports"
benign_series = benign_metrics[metric_name]

# calcular umbrales
thresholds = compute_thresholds(benign_series)
threshold = thresholds["IQR"]  # mejor opción para portscan

print("\n[Umbrales calculados:]")
for k, v in thresholds.items():
    print(f" - {k}: {v:.2f}")

print(f"\n[Umbral seleccionado]: {threshold:.2f} ({metric_name})")

# 1. gráfica comparativa de métodos
plot_portscan_comparison(metrics, thresholds, metric_name)

# 2. animación real-time
print("\n[Iniciando simulación animada PortScan]\n")
realtime_plot(metrics, threshold, metric_name, delay=REALTIME_DELAY)
