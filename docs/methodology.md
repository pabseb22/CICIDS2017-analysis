# Methodology

This document describes the methodology used throughout the CICIDS analysis pipeline.

## Overview
- Stage 1: Data acquisition and preparation
- Stage 2: Manual analysis using Wireshark and basic packet inspection
- Stage 3: Python-based automatic detection and metrics calculation

## Goals
- Demonstrate a reproducible analysis workflow
- Provide modular detectors for common attack types
- Document findings and produce reproducible results (metrics and images)

## Data sources
- Use public PCAPs and/or capture your own traffic.
- Do NOT upload real PCAPs to this repository; store them locally in `pcap_samples/`.

## Reproducibility
- Use `requirements.txt` and `src/` Python code to reproduce results.
- Store results under `results/` with `images/`, `logs/`, and `metrics/`.
