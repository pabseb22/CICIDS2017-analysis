import time
import os
import sys
import pandas as pd
import matplotlib.pyplot as plt


# ===========================
# CONFIG RUTAS
# ===========================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, "..", ".."))
sys.path.append(os.path.join(PROJECT_ROOT, "src"))

CSV_PATH = os.path.join(
    PROJECT_ROOT, "pcap_samples", "GeneratedLabelledFlows",
    "TrafficLabelling", "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
)

WINDOW_SECONDS = 1
REALTIME_DELAY = 0.10
THRESHOLD_STD_K = 4


# ===========================
# LOAD CSV — CORREGIDO
# ===========================
def load_csv(csv_path):
    print(f"\n[Cargando]: {csv_path}")
    df = pd.read_csv(csv_path, low_memory=False)

    # limpiar columnas
    df.columns = df.columns.str.strip()
    df.columns = df.columns.str.replace(r"[^\w\s/]", "", regex=True)

    # ahora sí Label existe como "Label"
    print("\n[Columnas detectadas]:")
    print(df.columns.tolist())

    # timestamp
    df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce")
    df = df.dropna(subset=["Timestamp"])
    df = df.sort_values("Timestamp")

    # shift de hora
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


# ===========================
# METRICAS
# ===========================
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


# ===========================
# VISUAL: DETECTION TIMELINE
# ===========================
def plot_detection_timeline(metrics, threshold):
    plt.figure(figsize=(14, 5))

    # línea principal
    plt.plot(metrics.index, metrics["flows_per_second"], label="Flows/s", linewidth=1.5)

    # threshold
    plt.axhline(threshold, color="orange", linestyle="--", linewidth=2, label="Threshold")

    # alertas en rojo
    alerts = metrics[metrics["flows_per_second"] > threshold]
    plt.scatter(alerts.index, alerts["flows_per_second"], color="red", label="ALERTA", s=25)

    plt.title("DDoS LOIT Detection Timeline")
    plt.xlabel("Tiempo")
    plt.ylabel("Flows por segundo")
    plt.grid(True)
    plt.legend()
    plt.tight_layout()

    plt.show()


def realtime_plot(metrics, threshold, delay=0.1):
    """
    Plot animado en tiempo real tipo IDS.
    """
    plt.ion()
    fig, ax = plt.subplots(figsize=(14, 5))

    x_vals = []
    y_vals = []
    alert_x = []
    alert_y = []

    (line,) = ax.plot([], [], label="Flows/s", linewidth=1.5)
    (alert_scatter,) = ax.plot([], [], "ro", label="Detección")
    ax.axhline(threshold, color="orange", linestyle="--", linewidth=2, label="Threshold")

    ax.set_title("Real-time DDoS Detection Timeline (Simulación)")
    ax.set_xlabel("Tiempo")
    ax.set_ylabel("Flows por segundo")
    ax.grid(True)
    ax.legend()

    for i, row in metrics.iterrows():
        ts = row.name
        flows = row["flows_per_second"]

        # actualizar buffers
        x_vals.append(ts)
        y_vals.append(flows)

        # actualizar línea principal
        line.set_xdata(x_vals)
        line.set_ydata(y_vals)

        # ajustar límites del gráfico dinámicamente
        ax.set_xlim(min(x_vals), max(x_vals))
        ax.set_ylim(0, max(y_vals) * 1.2)

        # detección → punto rojo
        if flows > threshold:
            alert_x.append(ts)
            alert_y.append(flows)
            alert_scatter.set_xdata(alert_x)
            alert_scatter.set_ydata(alert_y)

        # refrescar frame
        plt.pause(0.01)

        # sincronización con tu simulación real
        time.sleep(delay)

    plt.ioff()
    plt.show()


# ===========================
# STEP 1 — PREPROCESO
# ===========================
print("[Cargando dataset DDoS LOIT...]")

df = load_csv(CSV_PATH)

# crear ventana
df["window"] = df["Timestamp"].dt.floor("1s")

# métricas
metrics = compute_window_metrics(df)

# baseline benigno
benign = df[df["Label"] == "BENIGN"].copy()
benign_metrics = compute_window_metrics(benign)

baseline_mean = benign_metrics["flows_per_second"].mean()
baseline_std = benign_metrics["flows_per_second"].std()

threshold = baseline_mean + THRESHOLD_STD_K * baseline_std
print(f"[Umbral de alarma]: {threshold:.2f} flows/s")


# ===========================
# VISUALIZACIÓN DEL DETECTOR
# ===========================
plot_detection_timeline(metrics, threshold)
print("\n[Iniciando gráfica real-time animada]\n")
# ===========================
# STEP 2 — SIMULACIÓN REAL-TIME
# ===========================
realtime_plot(metrics, threshold, delay=REALTIME_DELAY)
