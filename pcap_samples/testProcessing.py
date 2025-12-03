# import pandas as pd
# import matplotlib.pyplot as plt

# # ==============================
# # 1. Cargar CSV
# # ==============================
# df = pd.read_csv("WednesdayCSV_Complete.csv")

# # Normalizar nombres
# df.columns = [c.strip().lower() for c in df.columns]

# # Tus columnas exactas son:
# # no, time, source, destination, protocol, length, ssid, info

# # ==============================
# # 2. Convertir tiempo
# # ==============================
# # "Time" en Wireshark es tiempo relativo en segundos (float)
# df["time"] = pd.to_datetime(df["time"], unit="s", origin="unix")

# # Agrupar por minuto
# df["minute"] = df["time"].dt.floor("min")

# # ==============================
# # 3. Encontrar los hosts más activos
# # ==============================
# top_dst = df["destination"].value_counts().head(5)
# top_src = df["source"].value_counts().head(5)

# print("\n=== Top 5 destinos con más tráfico ===")
# print(top_dst)

# print("\n=== Top 5 fuentes con más tráfico ===")
# print(top_src)

# # Filtrar dataset solo con los principales destinos
# df_top = df[df["destination"].isin(top_dst.index.tolist())]

# # ==============================
# # 4. Contar paquetes por minuto
# # ==============================
# traffic = df_top.groupby(["minute", "destination"]).size().reset_index(name="packets")

# # ==============================
# # 5. Graficar
# # ==============================
# plt.figure(figsize=(14,6))

# for dst in traffic["destination"].unique():
#     subset = traffic[traffic["destination"] == dst]
#     plt.plot(subset["minute"], subset["packets"], label=f"{dst}")

# plt.title("Trafico por minuto hacia los destinos más activos")
# plt.xlabel("Tiempo (minutos)")
# plt.ylabel("Paquetes por minuto")
# plt.legend()
# plt.grid(True)
# plt.tight_layout()
# plt.show()


import pandas as pd

df = pd.read_csv("WednesdayCSV.csv")
df.columns = [c.strip().lower() for c in df.columns]

# Convertir tiempo
df["time"] = pd.to_datetime(df["time"], unit="s", origin="unix")
df["minute"] = df["time"].dt.floor("min")

# Contar paquetes por minuto
counts = df.groupby("minute").size()

# Detectar minutos "anómalos"
umbral = counts.mean() + 3*counts.std()
anomalous_minutes = counts[counts > umbral]
print(anomalous_minutes)

# Obtener primer PAQUETE del primer minuto anómalo
attack_start_minute = anomalous_minutes.index[0]
first_packet = df[df["minute"] == attack_start_minute].iloc[0]

print("\n=== Primer paquete del ataque ===")
print(first_packet)

# Mostrar la fila y No. de Wireshark
print(f"\nPuedes abrir el paquete No. {first_packet['no.']} en Wireshark")
