"""Main orchestrator for CICIDS analysis

This script lists PCAPs under pcap_samples/ and runs all detectors. It writes
basic metrics and detector outputs to results/metrics/ and results/logs/.

Run (local):
    python -m src.main

Note: Do NOT add or commit PCAP files to the repository.
"""
from typing import List, Any
import os
import json
import datetime

from src.utils.pcap_reader import PcapReader, SCAPY_AVAILABLE
from src.utils.metrics import compute_basic_metrics, save_metrics
from src.detectors import dos_hulk_detector, slowloris_detector, portscan_detector, ddos_loit_detector


RESULTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'results')
RESULTS_DIR = os.path.abspath(RESULTS_DIR)
METRICS_DIR = os.path.join(RESULTS_DIR, 'metrics')
LOGS_DIR = os.path.join(RESULTS_DIR, 'logs')

os.makedirs(METRICS_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)


def run_all(pcaps: List[str]):
    reader = PcapReader()
    for p in pcaps:
        print(f"Processing {p}")
        try:
            pkts = reader.read_pcap(p)
        except ImportError as e:
            print("Cannot read pcap: Scapy not available.")
            pkts = []
        except Exception as e:
            print(f"Failed to read {p}: {e}")
            pkts = []

        # compute basic metrics
        metrics = compute_basic_metrics(pkts)
        ts = datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        base_name = os.path.basename(p).replace('.', '_')
        metrics_path = os.path.join(METRICS_DIR, f"metrics_{base_name}_{ts}.csv")
        save_metrics(metrics, metrics_path)
        print(f"Saved metrics: {metrics_path}")

        # Run detectors
        detectors = [dos_hulk_detector, slowloris_detector, portscan_detector, ddos_loit_detector]
        for det in detectors:
            try:
                rep = det.detect(pkts)
            except Exception as e:
                rep = {'error': str(e)}

            # write simple JSON report
            det_id = rep.get('detector', det.__name__)
            out_path = os.path.join(LOGS_DIR, f"{det_id}_{base_name}_{ts}.json")
            with open(out_path, 'w', encoding='utf-8') as fh:
                json.dump(rep, fh, indent=2)
            print(f"Wrote report for {det_id}: {out_path}")


if __name__ == "__main__":
    reader = PcapReader()
    pcaps = reader.list_pcaps()
    if len(pcaps) == 0:
        print("No PCAP files found under pcap_samples/. Add pcap files and retry. See pcap_samples/instructions.txt for guidance.")
    else:
        run_all(pcaps)
