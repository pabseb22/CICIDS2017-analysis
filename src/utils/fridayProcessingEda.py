
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, "..", ".."))

csv_file = os.path.join(PROJECT_ROOT, "pcap_samples", "GeneratedLabelledFlows","TrafficLabelling","Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")


import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# ===================================================
# 1. CARGA DEL CSV PROCESADO Y LIMPIEZA DE COLUMNAS
# ===================================================


df = pd.read_csv(csv_file)
df.columns = df.columns.str.strip()     # limpia espacios
print("[✔] CSV cargado:", df.shape)

# ==============================
# ATAQUES DEL VIERNES
# ==============================

friday_attacks = [
    "BENIGN",
    "DDoS",
    "PortScan",
    "Bot",
    "FTP-Patator",
    "SSH-Patator",
    "Web Attack � Brute Force",
    "Web Attack � XSS",
    "Web Attack � Sql Injection",
    "Infiltration",
    "Heartbleed"
]

df_fri = df[df["Label"].isin(friday_attacks)]
print("[✔] Subconjunto viernes:", df_fri.shape)
print(df_fri["Label"].value_counts())


# ===================================================
# 2. FUNCIONES DE GRAFICADO Y METRICAS
# ===================================================

def plot_distribution(data, column, title):
    plt.figure(figsize=(10,4))
    try:
        sns.kdeplot(data[column], fill=True)
    except:
        pass
    plt.title(title)
    plt.xlabel(column)
    plt.grid(True)
    plt.show()

def time_series(data, title):
    temp = data.copy()
    temp["Timestamp"] = pd.to_datetime(temp["Timestamp"])
    temp["sec"] = temp["Timestamp"].dt.floor("S")
    counts = temp.groupby("sec").size()
    
    plt.figure(figsize=(12,4))
    plt.plot(counts.index, counts.values)
    plt.title(title)
    plt.ylabel("Flujos/segundo")
    plt.grid(True)
    plt.show()

def metricas(data):
    return {
        "Total flujos": len(data),
        "Duración media": data["Flow Duration"].mean(),
        "Packets/s medio": data["Flow Packets/s"].mean(),
        "Bytes/s medio": data["Flow Bytes/s"].mean(),
        "Paquetes FWD medios": data["Total Fwd Packets"].mean(),
        "Paquetes BWD medios": data["Total Backward Packets"].mean(),
        "SYN mean": data["SYN Flag Count"].mean(),
        "ACK mean": data["ACK Flag Count"].mean()
    }


# ===================================================
# 3. ANALISIS POR ATAQUE
# ===================================================

for attack in friday_attacks:
    
    print("\n=========================================")
    print(f"      ANALISIS DE: {attack}")
    print("=========================================")

    atk = df_fri[df_fri["Label"] == attack]

    # -------- GRAFICAS PRINCIPALES --------
    
    plot_distribution(atk, "Flow Duration",
                      f"Duración de los flujos – {attack}")

    plot_distribution(atk, "Flow Packets/s",
                      f"Packets por segundo – {attack}")

    plot_distribution(atk, "Total Length of Fwd Packets",
                      f"Bytes enviados por flujo – {attack}")

    time_series(atk, f"Actividad temporal – {attack}")

    # -------- MÉTRICAS --------

    print("\n📊 MÉTRICAS RELEVANTES")
    m = metricas(atk)
    for k, v in m.items():
        print(f" - {k}: {v}")

print("\n[✔] Análisis del viernes completado.")
