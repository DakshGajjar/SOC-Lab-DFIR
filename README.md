# 🛡️ AI-Powered SOC Lab (Stand-alone Edition)

A fully containerized, automated SOC (Security Operations Center) laboratory environment featuring Wazuh, DFIR IRIS, Shuffle SOAR, and Ollama AI. This environment is designed for rapid deployment, threat hunting, and automated incident response using local AI.

## 🏗️ Architecture

```mermaid
graph TD
    subgraph "External Endpoints"
        HostAgent[Windows/Linux Agent]
    end

    subgraph "SOC Core (Podman/Docker)"
        WazuhMgr[Wazuh Manager]
        WazuhIdx[Wazuh Indexer - OpenSearch]
        WazuhDsh[Wazuh Dashboard]
        
        IRIS[DFIR IRIS - Case Management]
        Postgres[Postgres DB]
        
        Shuffle[Shuffle SOAR - Automation]
        Mongo[MongoDB]
        
        Ollama[Ollama AI - Local LLM]
    end

    subgraph "Management"
        Orchestrator[soc_deploy.py]
        Streamlit[soc_dashboard.py]
    end

    HostAgent -- Port 1514/1515 --> WazuhMgr
    WazuhMgr -- Alerts --> WazuhIdx
    WazuhDsh -- Visualize --> WazuhIdx
    
    Orchestrator -- Health Check --> WazuhMgr
    Orchestrator -- Health Check --> IRIS
    Orchestrator -- Health Check --> Shuffle
    
    Streamlit -- Triage --> Ollama
    Streamlit -- View Health --> Orchestrator
```

## 🚀 Features
*   **Wazuh 4.7.0**: Enterprise-grade SIEM and XDR.
*   **DFIR IRIS**: Advanced case management for security teams.
*   **Shuffle SOAR**: No-code automation for security workflows.
*   **Ollama AI**: Local AI analyst for automated alert triaging.
*   **One-Click Deployment**: Entire stack boots in < 5 minutes with a single command.
*   **Auto-Configuration**: Automatic SSL bypass and credential synchronization.

## 📋 Prerequisites
*   **Podman** (or Docker) with `podman-compose`.
*   **Python 3.9+**.
*   **Resources**: 8GB+ RAM recommended (16GB for best performance with Ollama).

## 🛠️ Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Deploy the Stack
```bash
python main.py deploy
```

### 3. Access the Dashboard
```bash
streamlit run soc_dashboard.py
```

## 🔐 Credentials Guide

All credentials are automatically generated and stored in a `.env` file during deployment.

| Service | URL | Default User |
| :--- | :--- | :--- |
| **Wazuh/OpenSearch** | [https://localhost:443](https://localhost:443) | `admin` |
| **DFIR IRIS** | [http://localhost:8000](http://localhost:8000) | `administrator` |
| **Shuffle SOAR** | [http://localhost:3443](http://localhost:3443) | *Created on first run* |
| **Ollama** | [http://localhost:11434](http://localhost:11434) | N/A |

> **Security Note:** Check the `.env` file or container logs for the randomly generated passwords.

## 📡 Adding Endpoints
To add your host machine or a VM:
1.  Install the **Wazuh Agent**.
2.  Point it to the Manager IP: `127.0.0.1` (if running locally).
3.  Ensure ports `1514` and `1515` are open in your firewall.

## 🧹 Maintenance
*   **Check Health:** `python soclab.py health`
*   **Stop Stack:** `python soclab.py destroy`
*   **Reset Environment:** `python soclab.py reset` (Wipes all data and starts fresh)

---
*Created with Antigravity*
