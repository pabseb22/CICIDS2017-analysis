import os
import subprocess

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, "..", ".."))

input_pcap = os.path.join(PROJECT_ROOT, "pcap_samples", "Wednesday-workingHours.pcap")
output_csv = os.path.join(PROJECT_ROOT, "pcap_samples", "extended_ids_export.csv")

TSHARK = r"C:\Program Files\Wireshark\tshark.exe"

# CAMPOS ESENCIALES PARA IDS + NMAP + DOS + BOTNET + L&S
fields = [
    "frame.number", "frame.time", "frame.len", "frame.protocols",

    "ip.src", "ip.dst", "ip.ttl", "ip.flags", "ip.flags.df", "ip.flags.mf",

    "tcp.srcport", "tcp.dstport", "tcp.seq", "tcp.ack", "tcp.flags",
    "tcp.flags.syn", "tcp.flags.fin", "tcp.flags.push", "tcp.flags.urg",
    "tcp.window_size_value", "tcp.len", "tcp.analysis.retransmission",

    "udp.srcport", "udp.dstport", "udp.length",

    "icmp.type", "icmp.code",

    "http.request.method", "http.request.uri", "http.request.full_uri",
    "http.host", "http.user_agent", "http.request.version",
    "http.content_length"
]

cmd = [
    TSHARK,
    "-r", input_pcap,
    "-T", "fields",
    "-E", "separator=,",
    "-E", "quote=d",
    "-E", "header=y"
]

# Añadir cada campo con -e
for f in fields:
    cmd += ["-e", f]

print("[*] Exportando CSV extendido para análisis IDS...")

# Ejecutar y guardar CSV
with open(output_csv, "w", encoding="utf-8") as f:
    subprocess.run(cmd, check=True, stdout=f)

print("\n[✔] CSV IDs extendido generado:")
print(output_csv)
