# Etapa 1 — Preparación del Entorno y Selección de PCAPs
Esta etapa explica cómo trabajar de forma eficiente con archivos CIC-IDS2017,
que pesan entre **8 y 13 GB**, evitando que Wireshark o la computadora se bloqueen.


## 1. PCAPs necesarios para el proyecto
Descargar manualmente desde:
🔗 https://www.unb.ca/cic/datasets/ids-2017.html

### Seleccionados:
- `Wednesday-WorkingHours.pcap` (ataques: Slowloris, SlowHTTPTest, Hulk, GoldenEye)
- `Friday-WorkingHours.pcap` (ataques: Nmap Port Scan, Botnet ARES, DDoS LOIT)

## 2. Cómo abrir PCAPs grandes sin que Wireshark se cuelgue

### ✔ Usar filtros al abrir (muy recomendado)
Ejemplo: abrir solo tráfico del atacante Kali
ip.src == 205.174.165.73

Para Friday (DDoS LOIT):
ip.dst == 192.168.10.50

Para análisis de ports scans:
tcp.flags.syn == 1 && tcp.flags.ack == 0

Esto reduce la carga inicial a menos del 1% del archivo.

## 3. Cortar PCAPs en fragmentos más pequeños (opcional)
Usar `editcap`:

### Por número de paquetes:
editcap -c 50000 Wednesday.pcap Wednesday-small.pcap

### Por tiempo:
editcap -A "10:40:00" -B "11:00:00" Wednesday.pcap Hulk.pcap

## 4. Intervalos de ataque relevantes
### Wednesday (DoS)
- Slowloris: 9:47–10:10
- SlowHTTPTest: 10:14–10:35
- Hulk: 10:43–11:00
- GoldenEye: 11:10–11:23

### Friday (Scanning + DDoS)
- Port Scan: 13:55–14:35
- Botnet ARES: 10:02–11:02
- DDoS LOIT: 15:56–16:16


## 5. Archivos organizados localmente
En `pcap_samples/` agregar:

INSTRUCTIONS: Place here your downloaded PCAPs.
Do NOT commit any PCAP files to GitHub.


---

## 6. Resultado de la etapa

Al finalizar esta etapa tendrás:

- El entorno configurado
- Los PCAPs descargados localmente
- Filtros identificados para cada ataque
- Intervalos de análisis claros
- Estructura del repositorio lista
