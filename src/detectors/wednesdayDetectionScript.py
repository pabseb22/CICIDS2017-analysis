import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, "..", ".."))
CSV_FILE = os.path.join(PROJECT_ROOT, "pcap_samples", "GeneratedLabelledFlows","TrafficLabelling","Wednesday-WorkingHours.pcap_ISCX.csv")

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import time

# =====================================
# CONFIGURACIÓN
# =====================================
WINDOW_SECONDS = 10
STEP_SECONDS = 5
REALTIME_SIM = True
SLEEP_SCALE = 2000

WED_ATTACKS = [
    "DoS Hulk",
    "DoS GoldenEye",
    "DoS slowloris",
    "DoS Slowhttptest",
    "BENIGN"
]

# =====================================
# CARGAR CSV
# =====================================
df = pd.read_csv(CSV_FILE)
df.columns = df.columns.str.strip()
df = df[df["Label"].isin(WED_ATTACKS)].copy()

df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce")
df.dropna(subset=["Timestamp"], inplace=True)
df = df.sort_values("Timestamp")

# columnas numéricas reales del dataset
num_cols = [
    "Flow Packets/s",
    "Flow Bytes/s",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets"
]

for c in num_cols:
    df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0)

# =====================================
# FUNCIÓN DE MÉTRICAS
# =====================================
def compute_metrics(win):
    if len(win) == 0:
        return None

    total_packets_s = win["Flow Packets/s"].sum()            # AGREGADO
    total_bytes_s = win["Flow Bytes/s"].sum()                # AGREGADO
    avg_duration = win["Flow Duration"].mean()               # AVERAGE
    avg_packets_per_flow = (win["Total Fwd Packets"] + win["Total Backward Packets"]).mean()

    return total_packets_s, total_bytes_s, avg_duration, avg_packets_per_flow

# =====================================
# FIGURA
# =====================================
plt.ion()
fig, ax = plt.subplots(figsize=(12,5))

times = []
pkts_s_values = []
thr_values = []

line_main, = ax.plot([], [], label="Packets/s (agregado)", color="blue")
line_thr, = ax.plot([], [], label="Umbral", color="orange")

ax.set_title("Detección Online – Miércoles CICIDS2017 (Packets/s)")
ax.set_xlabel("Tiempo simulado (s)")
ax.set_ylabel("Paquetes por segundo (agregado)")
ax.legend()
ax.grid(True)

# =====================================
# SIMULACIÓN
# =====================================
start = df["Timestamp"].min()
end = df["Timestamp"].max()
current = start

baseline_vals = []
alerts = []

window_delta = pd.Timedelta(seconds=WINDOW_SECONDS)
step_delta = pd.Timedelta(seconds=STEP_SECONDS)

print("[★] Iniciando detección dinámica...\n")

while current < end:

    win_end = current + window_delta
    win = df[(df["Timestamp"] >= current) & (df["Timestamp"] < win_end)]

    # ---------------------------
    # Saltar ventanas vacías
    # ---------------------------
    if len(win) == 0:
        current += step_delta
        continue

    metrics = compute_metrics(win)
    sim_t = (current - start).total_seconds()

    if metrics:
        pkts_s, bytes_s, avg_dur, avg_pkts = metrics

        # evitar NaN o inf aquí
        pkts_s = float(np.nan_to_num(pkts_s, nan=0.0, posinf=0.0, neginf=0.0))
        avg_dur = float(np.nan_to_num(avg_dur, nan=0.0, posinf=0.0, neginf=0.0))
        avg_pkts = float(np.nan_to_num(avg_pkts, nan=0.0, posinf=0.0, neginf=0.0))

        # baseline dinámico
        baseline_vals.append(pkts_s)

        if len(baseline_vals) > 20:
            med = np.median(baseline_vals)
            iqr = np.percentile(baseline_vals, 75) - np.percentile(baseline_vals, 25)
            thr = med + 3 * iqr
        else:
            thr = np.mean(baseline_vals) + np.std(baseline_vals)

        thr = float(np.nan_to_num(thr, nan=0.0, posinf=0.0, neginf=0.0))

        # detección volumétrica real
        volumetric = pkts_s > thr

        # detección low-slow
        low_slow = (
            avg_dur > np.median(df["Flow Duration"]) + 2*np.std(df["Flow Duration"]) and
            avg_pkts < max(1, np.median(df["Total Fwd Packets"]) * 0.5)
        )

        # actualizar gráfica
        times.append(sim_t)
        pkts_s_values.append(pkts_s)
        thr_values.append(thr)

        # imprimir alertas
        if volumetric:
            print(f"[ALERTA VOLUMETRICA] t={sim_t:.1f}s | pkts/s={pkts_s:.2f}")

        if low_slow:
            print(f"[ALERTA LOW-SLOW] t={sim_t:.1f}s | dur={avg_dur:.2f} | pkts/flow={avg_pkts:.2f}")

        # solo graficar si no hay NaN
        y_max = max(pkts_s_values + thr_values)
        if not np.isfinite(y_max):
            y_max = 1

        line_main.set_data(times, pkts_s_values)
        line_thr.set_data(times, thr_values)

        ax.set_xlim(max(0, sim_t - 200), sim_t + 10)
        ax.set_ylim(0, y_max * 1.2)

        fig.canvas.draw()
        fig.canvas.flush_events()

    if REALTIME_SIM:
        time.sleep(WINDOW_SECONDS / SLEEP_SCALE)

    current += step_delta

print("\n[✔] Detección finalizada.")
