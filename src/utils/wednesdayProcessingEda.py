import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, "..", ".."))

csv_file = os.path.join(PROJECT_ROOT, "pcap_samples", "GeneratedLabelledFlows","TrafficLabelling","Wednesday-WorkingHours.pcap_ISCX.csv")

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# =============================
# 1. CARGA DEL CSV PROCESADO
# =============================

df = pd.read_csv(csv_file)

print("[✔] Archivo cargado:")
print(df.shape)


# =============================
# 2. FILTRAR SOLO ATAQUES DEL MIÉRCOLES
# =============================

wednesday_attacks = [
    "DoS Hulk",
    "DoS GoldenEye",
    "DoS slowloris",
    "DoS Slowhttptest"
]

print("[✔] Archivo cargado:", df.shape)

# Fix: limpiar nombres de columnas (quita espacios y caracteres raros)
df.columns = df.columns.str.strip()


# detectar nombre real de la columna Label
label_col = [c for c in df.columns if "label" in c.lower()][0]

print(f"[✔] Columna de etiquetas detectada: {label_col}")

df_wed = df[df[label_col].isin(wednesday_attacks + ["BENIGN"])]


print("\n[✔] Subconjunto del miércoles:")
print(df_wed["Label"].value_counts())


# =============================
# 3. FUNCIONES DE ANALISIS Y GRAFICO
# =============================

def plot_distribution(data, column, title):
    plt.figure(figsize=(10,4))
    sns.kdeplot(data[column], fill=True)
    plt.title(title)
    plt.xlabel(column)
    plt.grid(True)
    plt.show()

def plot_bar_counts(data, title):
    plt.figure(figsize=(8,4))
    data["Label"].value_counts().plot(kind="bar")
    plt.title(title)
    plt.ylabel("Cantidad de flujos")
    plt.grid(True)
    plt.show()

def time_series_count(data, title):
    temp = data.copy()
    temp["Timestamp"] = pd.to_datetime(temp["Timestamp"])
    temp["time_sec"] = temp["Timestamp"].dt.floor("S")
    counts = temp.groupby("time_sec").size()

    plt.figure(figsize=(12,4))
    plt.plot(counts.index, counts.values)
    plt.title(title)
    plt.xlabel("Tiempo")
    plt.ylabel("Flujos/segundo")
    plt.grid(True)
    plt.show()

def metricas_relevantes(data):
    metrics = {
        "Total flujos": len(data),
        "Duración promedio": data["Flow Duration"].mean(),
        "Promedio bytes/flujo": data["Total Length of Fwd Packets"].mean(),
        "Promedio paquetes/flujo": data["Total Fwd Packets"].mean(),
        "Promedio Packets/s": data["Flow Packets/s"].mean(),
        "Promedio Bytes/s": data["Flow Bytes/s"].mean(),
        "SYN Flag Count Prom": data["SYN Flag Count"].mean(),
        "ACK Flag Count Prom": data["ACK Flag Count"].mean(),
    }
    return metrics


# =============================
# 4. ANALISIS POR ATAQUE
# =============================

for attack in wednesday_attacks:
    
    print("\n=================================")
    print(f" ANALISIS PARA: {attack}")
    print("=================================")

    data = df_wed[df_wed["Label"] == attack]
    
    print(f"Total flujos: {len(data)}")

    # ---- GRAFICAS ----

    plot_distribution(data, "Flow Duration",
                      f"Distribución duración del flujo – {attack}")

    plot_distribution(data, "Total Length of Fwd Packets",
                      f"Bytes enviados por flujo – {attack}")

    plot_distribution(data, "Flow Packets/s",
                      f"Packets por segundo – {attack}")

    time_series_count(data, f"Actividad del ataque en el tiempo – {attack}")

    # ---- METRICAS ----
    print("\n[📊 MÉTRICAS IMPORTANTES]")
    for k, v in metricas_relevantes(data).items():
        print(f"- {k}: {v}")
