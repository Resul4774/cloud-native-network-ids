# Cloud-Native Network IDS & Observability Stack

A high-performance, containerized Network Intrusion Detection System (IDS) and real-time network traffic analysis stack. This project sniffs live network packets directly from the host network interface, detects anomalies like Port Scans or ICMP Floods, and exposes production-ready metrics to a Prometheus and Grafana visualization dashboard.

## 🏗️ Architecture & Core Workflow
1. **Packet Sniffer (Python & Scapy):** Attaches to the host network interface inside a privileged Docker container to analyze incoming layers (IP, TCP, ICMP) in real-time.
2. **Metrics Exporter (Prometheus Client):** Converts raw network statistics into structural metrics and exposes them via an HTTP endpoint on port `8000`.
3. **Time-Series Database (Prometheus):** Scrapes the exposed endpoint every 5 seconds to register anomalies and packet distribution densities.
4. **Visualization Layer (Grafana):** Visualizes the metrics on a professional Security Operations Center (SOC) dashboard.

## 🛠️ Tech Stack & Infrastructure
- **OS:** Ubuntu Server LTS (CLI-only environment)
- **Core Engine:** Python 3.11 / Scapy
- **Containerization:** Docker / Custom Dockerfile (Thin-provisioned base image)
- **Orchestration:** Docker Compose (Host network mode)
- **Monitoring:** Prometheus & Grafana Stack

## 🚀 Quick Start & Deployment

Clone the repository to your local server infrastructure:
```bash
git clone git@github.com:Resul4774/cloud-native-network-ids.git
cd cloud-native-network-ids
```

Build the custom packet sniffer engine container:
```bash
docker build --no-cache -t network-sniffer .
```

Fire up the sniffer engine with raw network interface access privileges:
```bash
docker run -d --name my-sniffer --net=host --privileged network-sniffer
```

Launch the Prometheus and Grafana telemetry stack concurrently using Docker Compose:
```bash
docker compose up -d
```

Access your metrics dashboard at `http://localhost:3000` (Default Credentials: `admin` / `admin`).

## 📊 Structural Prometheus Metrics Exposed
- `ids_packets_processed_total`: Total processed network packets grouped by protocol (`TCP`, `ICMP`, `OTHER`).
- `ids_port_scan_alerts_total`: Incremental counters for detected sequential scan behaviors per source IP.
- `ids_icmp_flood_alerts_total`: Registered alerts for malicious ICMP flood/DDoS indicators.
- `ids_unauthorized_ssh_alerts_total`: Tracks raw connection flags attempts targetting Port 22.

## 📜 License
This project is open-source and available under the [MIT License](LICENSE).
