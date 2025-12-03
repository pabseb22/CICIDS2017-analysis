# Stage 3: Python-based Detection and Metrics

In this stage, we use Python scripts to automatically detect attack patterns and compute metrics for reporting.

## Key Components
- `src/utils/` - helper code for PCAP reading and metrics calculation
- `src/detectors/` - modular detectors for individual attack types
- `src/main.py` - orchestrator script to run detectors and outputs

## Typical workflow
1. Parse PCAPs with a reader (Scapy or PyShark) and convert to structured records
2. Run detectors on the parsed data
3. Write results (metrics, logs, images) into `results/`
4. Generate a report or analysis notebook

## Output
- `.csv` / `.json` metrics under `results/metrics`
- Visualizations under `results/images`
- Logs under `results/logs`

## Extensibility
- Add new detector modules to `src/detectors/` and register them in `src/main.py`

