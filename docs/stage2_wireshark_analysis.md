# Etapa 2 — Análisis Forense del Tráfico en Wireshark

Esta etapa documenta el procedimiento para identificar ataques dentro
de los PCAPs del dataset CIC-IDS2017, utilizando filtros eficientes y
extrayendo patrones característicos para ser usados luego en scripts
de detección.

---

# 1. Archivos utilizados
- **Wednesday-WorkingHours.pcap** (≈ 13 GB)
- **Friday-WorkingHours.pcap** (≈ 8 GB)

Estos archivos contienen múltiples ataques ejecutados de forma controlada,
con horarios exactos publicados oficialmente en la documentación del dataset.

---

# 2. Filtros esenciales para trabajar con PCAPs grandes

Para evitar cargar millones de paquetes, se recomienda filtrar desde el inicio:

## 2.1 Tráfico del atacante Kali Linux (principal atacante del dataset)

ip.src == 205.174.165.73

## 2.2 Tráfico hacia el servidor víctima (Web Server Ubuntu)

ip.dst == 192.168.10.50

## 2.3 Filtrar tráfico TCP malicioso general

### SYN sin ACK (escaneo + DoS)
tcp.flags.syn == 1 && tcp.flags.ack == 0

### Respuestas SYN/ACK (puertos abiertos)
tcp.flags.syn == 1 && tcp.flags.ack == 1

### RST (puertos cerrados)
tcp.flags.reset == 1

## 2.4 Filtrar HTTP (Hulk, GoldenEye, SlowHTTPTest)
http.request

## 2.5 Filtrar ataques lentos tipo Slowloris
tcp.len == 0

nginx
Copy code
o  
tcp.analysis.retransmission
para identificar conexiones largas e incompletas.

## 2.6 Filtrar ataques distribuidos DDoS LOIT
(ip.src == 205.174.165.69) || (ip.src == 205.174.165.70) || (ip.src == 205.174.165.71)

yaml
Copy code

---

# 3. Identificación de ataques por intervalos

Los ataques en CIC-IDS2017 ocurrieron en momentos específicos.
Aquí se describe cómo localizar cada uno.

---

# 3.1 Wednesday (DoS)

## 3.1.1 DoS Hulk (10:43–11:00)
- Filtrar por método HTTP GET:
http.request.method == "GET"

markdown
Copy code
- Comportamiento esperado:
  - Miles de GET consecutivos
  - Picos en I/O Graphs
  - IP del atacante predominante

## 3.1.2 Slowloris (9:47–10:10)
- Filtro recomendado:
tcp.len == 0

markdown
Copy code
- Comportamiento:
  - Muchas conexiones abiertas sin enviar datos
  - Tiempos muy largos entre paquetes
  - Recursos del servidor agotados lentamente

## 3.1.3 SlowHTTPTest (10:14–10:35)
- Filtro:
http.request && frame.len < 100

markdown
Copy code
- Comportamiento:
  - Peticiones HTTP incompletas
  - Trafico lento tipo “goteo”

## 3.1.4 GoldenEye (11:10–11:23)
- Filtro:
http.user_agent contains "goldeneye"

yaml
Copy code
- Comportamiento:
  - Variación artificial de User-Agent
  - Solicitudes HTTP intensas

---

# 3.2 Friday (Scanning + DDoS)

## 3.2.1 Port Scan (13:55–14:35)
- Filtro:
tcp.flags.syn == 1 && tcp.flags.ack == 0

markdown
Copy code
- Comportamiento:
  - Múltiples puertos destino secuenciales
  - Respuestas SYN/ACK y RST según estado del puerto
  - Escaneo tipo Nmap

## 3.2.2 Botnet ARES (10:02–11:02)
- Filtro:
ip.src == 192.168.10.5 || ip.src == 192.168.10.8 || ip.src == 192.168.10.9 || ip.src == 192.168.10.14 || ip.src == 192.168.10.15

markdown
Copy code
- Comportamiento:
  - Múltiples hosts internos conectándose a un C2
  - Patrones coordinados

## 3.2.3 DDoS LOIT (15:56–16:16)
- Filtro:
ip.dst == 192.168.10.50

nginx
Copy code
y
ip.src == 205.174.165.69 || ip.src == 205.174.165.70 || ip.src == 205.174.165.71

yaml
Copy code
- Comportamiento:
  - Tráfico masivo simultáneo
  - Paquetes muy frecuentes y volumétricos
  - Patrones distribuidos de ataque

---

# 4. Capturas clave para la presentación

Se recomienda capturar:

### ✔ Listado de paquetes con filtros aplicados  
### ✔ Detalle del paquete (IP + TCP/HTTP headers)  
### ✔ Gráficos I/O (Statistics → I/O Graphs) para visualizar picos  
### ✔ Conversations (Statistics → Conversations → TCP)  
### ✔ Endpoints (Statistics → Endpoints → IPv4)  
### ✔ Streams relevantes (Follow TCP Stream)

---

# 5. Conclusiones de la Etapa

En esta etapa se logran:
- Aislar ataques dentro de PCAPs masivos.
- Identificar patrones de DoS, DDoS y PortScan.
- Obtener evidencia visual para la defensa oral.
- Preparar las métricas necesarias para la siguiente etapa.

Esta evidencia será utilizada para construir los detectores en Python
en la Etapa 3.