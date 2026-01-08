# Ethlambda Metrics Stack

This directory contains a complete Grafana + Prometheus monitoring stack for the ethlambda Lean Ethereum consensus client.
The dashboards used are the standard ones provided in [Lean Ethereum Metrics Specifications](https://github.com/leanEthereum/leanMetrics).

## Overview

The metrics stack provides:

- **Prometheus**: Time-series database for collecting and storing metrics
- **Grafana**: Visualization platform with pre-configured dashboards
- **Lean Metrics Dashboards**: Official dashboards from the [leanMetrics](https://github.com/leanEthereum/leanMetrics) repository

## Quick Start

### Prerequisites

- Docker and Docker Compose installed
- Ethlambda client running with metrics endpoint enabled (default: `http://localhost:8008/metrics`)

### Starting the Stack

```bash
# From the metrics directory
docker compose -f docker-compose-metrics.yaml up -d
```

This will start:

- Prometheus on `http://localhost:9090`
- Grafana on `http://localhost:3000`

### Accessing Grafana

1. Open your browser to `http://localhost:3000`
2. Navigate to Dashboards to view:
   - **Lean Ethereum Client Dashboard**: Single-client metrics view
   - **Lean Ethereum Client Interop Dashboard**: Multi-client comparison view

### Stopping the Stack

```bash
docker compose -f docker-compose-metrics.yaml down
```

To remove all data volumes:

```bash
docker compose -f docker-compose-metrics.yaml down -v
```
