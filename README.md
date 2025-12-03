# Network Traffic Analysis using CIC-IDS2017
Proyecto final del curso de Redes de Computadores — Pablo Alvarado (USFQ)

## 📌 Descripción General
Este proyecto analiza tráfico real capturado en el dataset **CIC-IDS2017**, utilizando Wireshark y Python para:
- Identificar patrones de ataques DoS/DDoS.
- Detectar escaneo de puertos (Nmap).
- Extraer métricas relevantes del tráfico.
- Desarrollar scripts simples de detección basados en umbrales adaptativos.

El objetivo es demostrar cómo los conceptos del modelo TCP/IP, protocolos de red y fundamentos de seguridad
pueden aplicarse en el análisis forense y en la detección básica de anomalías.



## 🎯 Objetivos del Proyecto
- Analizar PCAPs reales de CIC-IDS2017 con herramientas profesionales.
- Identificar firmas y comportamientos asociados a ataques de red.
- Implementar detectores sencillos de DoS, DDoS y port scanning usando Python.
- Evaluar la efectividad del análisis mediante métricas reproducibles.
- Documentar la metodología para facilitar replicación.



## 📂 Estructura del Proyecto
Ver explicación detallada en `/docs`.



## 📥 Descarga del Dataset (NO incluido en este repositorio)
Por su tamaño (8–12 GB por archivo), los PCAPs utilizados deben descargarse manualmente desde:

🔗 https://www.unb.ca/cic/datasets/ids-2017.html

### PCAPs necesarios:
- `Wednesday-WorkingHours.pcap`
- `Friday-WorkingHours.pcap`

Los intervalos de ataque están documentados en `/docs/stage1_preparation.md`.



## ⚙ Requisitos
```bash
pip install -r requirements.txt
🚀 Cómo ejecutarlo
python src/main.py
```

### 📑 Metodología y pasos del proyecto
Etapa 1: Preparación del entorno y selección de datos
Etapa 2: Análisis forense en Wireshark
Etapa 3: Extracción de métricas
Etapa 4: Detección con Python
Etapa 5: Resultados y presentación

Todos los detalles se encuentran en docs/.

## ⚠ Nota
Este repositorio no contiene PCAPs por razones éticas, de tamaño y licencia.
Sin embargo, todo el análisis es totalmente reproducible siguiendo las instrucciones.
