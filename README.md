# 🔍 Ingressor

**Multi-cluster Kubernetes service discovery for external domains**

[![CI](https://github.com/scottidler/ingressor/actions/workflows/ci.yml/badge.svg)](https://github.com/scottidler/ingressor/actions/workflows/ci.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Ingressor is a service discovery tool that crawls multiple Kubernetes clusters to find and catalog all external domains exposed via Ingress resources and Istio VirtualServices. Perfect for organizations running services across multiple clusters and environments who need a centralized view of all their external endpoints.

## ✨ Features

- **Multi-cluster Discovery**: Scan multiple Kubernetes clusters simultaneously
- **Dual Resource Support**: Discovers domains from both Ingress and Istio VirtualService resources
- **Environment Awareness**: Organizes services by environment (prod, staging, test, etc.)
- **Beautiful Web Dashboard**: Clean, responsive UI with filtering and search capabilities
- **REST API**: Full REST API for programmatic access to discovered services
- **Flexible Configuration**: YAML-based configuration with regex filtering
- **Real-time Updates**: Periodic scanning with configurable intervals
- **TLS Detection**: Identifies which services have TLS/SSL enabled
- **Docker Ready**: Containerized deployment with Docker Compose examples
- **Structured Logging**: Comprehensive logging with structlog, configurable via environment variables

## 🚀 Quick Start

### Installation

```bash
# Install from PyPI (when published)
uv pip install ingressor

# Or install from source
git clone https://github.com/scottidler/ingressor.git
cd ingressor
uv pip install -e .
```

### Basic Usage

1. **Generate a sample configuration:**
   ```bash
   ingressor init-config -o config.yaml
   ```

2. **Edit the configuration** to match your clusters:
   ```yaml
   clusters:
     - name: prod-us-west-1
       kubeconfig_path: ~/.kube/config
       context: prod-us-west-1
       environment: prod
       enabled: true
     - name: staging-us-west-1
       kubeconfig_path: ~/.kube/config
       context: staging-us-west-1
       environment: staging
       enabled: true
   
   domain_filter: .*\.tatari\.dev$  # Only scan *.tatari.dev domains
   scan_interval: 300  # Scan every 5 minutes
   ```

3. **Start the server:**
   ```bash
   ingressor serve --config config.yaml
   ```

4. **Access the dashboard** at http://localhost:8000

## 📖 Documentation

### Configuration

The configuration file supports the following options:

```yaml
clusters:
  - name: cluster-name          # Unique cluster identifier
    kubeconfig_path: ~/.kube/config  # Path to kubeconfig
    context: cluster-context    # Kubernetes context name
    environment: prod           # Environment label (prod, staging, test, etc.)
    region: us-west-1          # Optional region
    enabled: true              # Whether to scan this cluster

scan_interval: 300             # Scan interval in seconds
domain_filter: .*\.example\.com$  # Regex filter for domains
include_namespaces: []         # Specific namespaces to include (empty = all)
exclude_namespaces:            # Namespaces to exclude
  - kube-system
  - kube-public
enable_istio: true            # Enable Istio VirtualService discovery
enable_ingress: true          # Enable Ingress discovery
```

### Logging Configuration

Ingressor uses structured logging with `structlog`. You can configure logging behavior using environment variables:

```bash
# Set log level (DEBUG, INFO, WARNING, ERROR)
export LOG_LEVEL=DEBUG

# Set log format (console or json)
export LOG_FORMAT=json

# Or use the --verbose flag for debug logging
ingressor --verbose serve --config config.yaml
```

**Log Levels:**
- `DEBUG`: Detailed debugging information including function entry/exit
- `INFO`: General operational messages (default)
- `WARNING`: Warning messages for non-critical issues
- `ERROR`: Error messages for failures

**Log Formats:**
- `console`: Human-readable colored output (default)
- `json`: Structured JSON output for production/log aggregation
```

### CLI Commands

```bash
# Start the web server and API
ingressor serve --config config.yaml --host 0.0.0.0 --port 8000

# One-time scan and output results
ingressor scan --config config.yaml --output table
ingressor scan --config config.yaml --output json --environment prod

# Configuration management
ingressor init-config                    # Generate sample config
ingressor validate-config --config config.yaml  # Validate config file

# Get version info
ingressor version
```

### REST API Endpoints

- `GET /` - Web dashboard
- `GET /health` - Health check
- `GET /domains` - List all discovered domains
- `GET /domains?environment=prod` - Filter by environment
- `GET /domains/{domain}` - Get specific domain info
- `GET /summary` - Get summary statistics
- `GET /environments` - List all environments
- `GET /clusters` - List all clusters
- `POST /scan` - Trigger manual scan

### Docker Deployment

```bash
# Using Docker Compose
cd examples/
docker-compose up -d

# Or with Docker directly
docker build -t ingressor .
docker run -p 8000:8000 -v ~/.kube:/root/.kube:ro ingressor
```

## 🛠️ Development

### Setup Development Environment

```bash
git clone https://github.com/scottidler/ingressor.git
cd ingressor

# Install with development dependencies
uv pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install

# Run tests
pytest

# Run linting
ruff check .
ruff format .

# Type checking
mypy ingressor
```

### Project Structure

```
ingressor/
├── ingressor/           # Main package
│   ├── __init__.py     # Package initialization
│   ├── models.py       # Pydantic data models
│   ├── core.py         # Core discovery logic
│   ├── api.py          # FastAPI REST API
│   ├── web.py          # Web dashboard HTML generation
│   └── cli.py          # Command-line interface
├── tests/              # Test suite
├── examples/           # Usage examples and configs
├── .github/workflows/  # CI/CD workflows
└── docs/              # Documentation
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with [FastAPI](https://fastapi.tiangolo.com/) for the REST API
- Uses [Kubernetes Python Client](https://github.com/kubernetes-client/python) for cluster interaction
- Styled with modern CSS and responsive design principles
