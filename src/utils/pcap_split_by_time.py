# import os
# import subprocess
# import glob
# from datetime import datetime

# # === RUTAS BASE DEL PROYECTO ===
# BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, "..", ".."))

# input_pcap = os.path.join(PROJECT_ROOT, "pcap_samples", "Wednesday-workingHours.pcap")
# cut_dir = os.path.join(PROJECT_ROOT, "pcap_samples", "cuts")
# output_final = os.path.join(PROJECT_ROOT, "pcap_samples", "hulk_attack_final.pcap")

# os.makedirs(cut_dir, exist_ok=True)

# # === RUTAS A LAS HERRAMIENTAS WIRESHARK ===
# EDITCAP = r"C:\Program Files\Wireshark\editcap.exe"
# TSHARK = r"C:\Program Files\Wireshark\tshark.exe"
# MERGECAP = r"C:\Program Files\Wireshark\mergecap.exe"

# # === INTERVALO EXACTO DEL ATAQUE HULK ===
# start_str = "Jul 5, 2017 10:43:00"
# end_str   = "Jul 5, 2017 11:00:00"

# start_dt = datetime.strptime(start_str, "%b %d, %Y %H:%M:%S")
# end_dt   = datetime.strptime(end_str, "%b %d, %Y %H:%M:%S")

# attacker = "205.174.165.73"
# victim   = "205.174.165.68"

# # print("[1] Dividiendo archivo en fragmentos...")
# # subprocess.run([
# #     EDITCAP, "-c", "500000",
# #     input_pcap,
# #     os.path.join(cut_dir, "cut.pcap")
# # ], check=True)

# print("[2] Identificando fragmentos relevantes...")
# fragments = sorted(glob.glob(os.path.join(cut_dir, "*.pcap")))
# valid_parts = []

# for frag in fragments:
#     try:
#         # Leer timestamp del primer paquete
#         result = subprocess.check_output([
#             TSHARK, "-r", frag, "-c", "1", "-T", "fields", "-e", "frame.time"
#         ]).decode(errors="ignore").strip()

#         if result:
#             # Convertir timestamp
#             t = datetime.strptime(result[:24], "%b %d, %Y %H:%M:%S")

#             # Ver si está dentro del intervalo exacto
#             if start_dt <= t <= end_dt:
#                 valid_parts.append(frag)

#     except Exception as e:
#         print("Error leyendo fragmento:", frag, e)

# print("[*] Fragmentos válidos encontrados:")
# for p in valid_parts:
#     print("   →", p)

# if not valid_parts:
#     print("\n[❌] ERROR: No se detectó ningún fragmento con el intervalo del ataque.")
#     print("    Vamos a necesitar inspeccionar manualmente un fragmento.")
#     exit(1)

# output_parts = []

# print("[3] Filtrando fragmentos seleccionados...")
# for frag in valid_parts:
#     out = frag.replace(".pcap", "_HULK.pcap")
#     subprocess.run([
#         TSHARK, "-r", frag,
#         "-Y", f'frame.time >= "{start_str}" && frame.time <= "{end_str}" && '
#               f'(ip.addr == {attacker} || ip.addr == {victim})',
#         "-w", out
#     ], check=True)

#     output_parts.append(out)

# print("[4] Fusionando resultados...")
# subprocess.run([MERGECAP, "-w", output_final] + output_parts, check=True)

# print("\n[✔] Listo. Archivo final generado:")
# print(output_final)

# import os
# import subprocess

# # === BASE DEL PROYECTO (esto corrige todas las rutas) ===
# BASE_DIR = os.path.dirname(os.path.abspath(__file__))          # .../src/utils
# PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, "..", ".."))   # .../CICIDS2017-analysis

# input_pcap = os.path.join(PROJECT_ROOT, "pcap_samples", "Wednesday-workingHours.pcap")
# output_pcap = os.path.join(PROJECT_ROOT, "pcap_samples", "hulk_attack.pcap")

# print("Script folder:", BASE_DIR)
# print("Project root:", PROJECT_ROOT)
# print("Input file:", input_pcap)
# print("Exists?:", os.path.exists(input_pcap))

# if not os.path.exists(input_pcap):
#     raise FileNotFoundError("PCAP INPUT FILE NOT FOUND")

# # === RUTAS A TSHARK ===
# TSHARK = r"C:\Program Files\Wireshark\tshark.exe"

# # === INTERVALO DEL ATAQUE HULK ===
# start = "Jul 5, 2017 10:43:00"
# end   = "Jul 5, 2017 11:00:00"
# attacker = "205.174.165.73"
# victim   = "205.174.165.68"

# # === EJECUTAR EXTRACCIÓN ===
# print("[*] Ejecutando filtro con tshark...")

# subprocess.run([
#     TSHARK,
#     "-r", input_pcap,
#     "-Y", f'frame.time >= "{start}" && frame.time <= "{end}" && '
#           f'(ip.addr == {attacker} || ip.addr == {victim})',
#     "-w", output_pcap
# ], check=True)

# print("\n[✔] PCAP generado correctamente:")
# print(output_pcap)

import os
import subprocess

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, "..", ".."))

input_pcap = os.path.join(PROJECT_ROOT, "pcap_samples", "Wednesday-workingHours.pcap")
output_pcap = os.path.join(PROJECT_ROOT, "pcap_samples", "hulk_attack.pcap")

TSHARK = r"C:\Program Files\Wireshark\tshark.exe"

attacker = "205.174.165.73"
victim_public = "205.174.165.68"

# ✔ 100% compatible con Windows (NO usa comillas internas)
display_filter = (
    f"ip.src == {attacker} && "
    f"ip.dst == {victim_public} && "
    f"tcp.dstport == 80 && "
    f"http.request.method == GET"
)

print("[*] Extrayendo ataque HULK (filtro robusto)...")

subprocess.run([
    TSHARK,
    "-r", input_pcap,
    "-Y", display_filter,
    "-w", output_pcap
], check=True)

print("\n[✔] PCAP generado correctamente:")
print(output_pcap)
