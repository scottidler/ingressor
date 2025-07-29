# 🚀 Ingressor Deployment Guide

This guide covers all deployment options for Ingressor, from development to production environments.

## 📋 Overview

Ingressor supports **flexible deployment models** to fit different organizational needs:

- **🖥️ External/Centralized**: Run outside Kubernetes clusters (laptop, CI/CD, management server)
- **☸️ In-Cluster**: Deploy as a pod inside one of your Kubernetes clusters
- **🔄 Hybrid**: Mix of both approaches for different use cases

## 🔐 Authentication Mechanisms

Ingressor uses two different authentication methods depending on deployment location:

### External Authentication (kubeconfig files)
```yaml
clusters:
  - name: prod-cluster
    kubeconfig_path: ~/.kube/config  # Path to kubeconfig file
    context: prod-context           # Kubernetes context name
    environment: prod
    enabled: true
```

### In-Cluster Authentication (ServiceAccount tokens)
```yaml
clusters:
  - name: local-cluster
    kubeconfig_path: null  # Uses in-cluster ServiceAccount
    context: null
    environment: prod
    enabled: true
```

## 🖥️ External/Centralized Deployment

### Use Cases
- **Development & Testing**: Quick setup on your laptop
- **CI/CD Integration**: Run scans in build pipelines
- **Centralized Management**: Single management server for all clusters
- **Multi-cloud**: Scanning clusters across different cloud providers

### Prerequisites
- Access to all target Kubernetes clusters
- Valid kubeconfig file(s) with appropriate contexts
- Network connectivity to cluster API servers

### Setup Steps

#### 1. Install Ingressor
```bash
# From PyPI (when published)
uv pip install ingressor

# Or from source
git clone https://github.com/scottidler/ingressor.git
cd ingressor
uv pip install -e .
```

#### 2. Generate Configuration
```bash
# Generate sample config
ingressor init-config -o config.yaml
```

#### 3. Configure Clusters
Edit `config.yaml` with your cluster details:

```yaml
clusters:
  - name: prod-us-west-1
    kubeconfig_path: ~/.kube/config
    context: prod-us-west-1
    environment: prod
    region: us-west-1
    enabled: true
  - name: staging-us-west-1
    kubeconfig_path: ~/.kube/config
    context: staging-us-west-1
    environment: staging
    region: us-west-1
    enabled: true
  - name: test-eu-west-1
    kubeconfig_path: ~/.kube/eu-config
    context: test-eu-west-1
    environment: test
    region: eu-west-1
    enabled: true

scan_interval: 300
domain_filter: .*\.yourcompany\.com$
exclude_namespaces:
  - kube-system
  - kube-public
  - istio-system
enable_istio: true
enable_ingress: true
```

#### 4. Validate Configuration
```bash
# Test configuration
ingressor validate-config --config config.yaml

# Test cluster connectivity
ingressor scan --config config.yaml --output table
```

#### 5. Run the Service
```bash
# Start the web server
ingressor serve --config config.yaml --host 0.0.0.0 --port 8000

# Access dashboard at http://localhost:8000
```

### Docker Deployment (External)
```bash
# Build image
docker build -t ingressor .

# Run with mounted kubeconfig
docker run -d \
  --name ingressor \
  -p 8000:8000 \
  -v ~/.kube:/root/.kube:ro \
  -v $(pwd)/config.yaml:/app/config.yaml:ro \
  ingressor serve --config /app/config.yaml --host 0.0.0.0
```

### Docker Compose (External)
```yaml
version: '3.8'
services:
  ingressor:
    build: .
    ports:
      - "8000:8000"
    volumes:
      - ~/.kube:/root/.kube:ro
      - ./config.yaml:/app/config.yaml:ro
    environment:
      - LOG_FORMAT=json
    command: ["ingressor", "serve", "--config", "/app/config.yaml", "--host", "0.0.0.0"]
    restart: unless-stopped
```

## ☸️ In-Cluster Deployment

### Use Cases
- **Production Environments**: Cloud-native deployment following Kubernetes patterns
- **Security**: Reduced external dependencies and network exposure
- **High Availability**: Kubernetes-managed lifecycle and health checks
- **Resource Management**: Kubernetes resource limits and monitoring

### Prerequisites
- Kubernetes cluster with RBAC enabled
- Ability to create ServiceAccounts, ClusterRoles, and Deployments
- Kubeconfig files for external clusters (if scanning multiple clusters)

### Setup Steps

#### 1. Create Namespace
```bash
kubectl create namespace ingressor-system
```

#### 2. Create RBAC Resources
```yaml
# rbac.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ingressor
  namespace: ingressor-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ingressor
rules:
- apiGroups: ["networking.k8s.io"]
  resources: ["ingresses"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["networking.istio.io"]
  resources: ["virtualservices"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ingressor
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: ingressor
subjects:
- kind: ServiceAccount
  name: ingressor
  namespace: ingressor-system
```

#### 3. Create Configuration
```yaml
# config-configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: ingressor-config
  namespace: ingressor-system
data:
  config.yaml: |
    clusters:
      # Local cluster (uses in-cluster auth)
      - name: local-cluster
        kubeconfig_path: null
        context: null
        environment: prod
        region: us-west-1
        enabled: true
      # External clusters (uses mounted kubeconfigs)
      - name: staging-cluster
        kubeconfig_path: /etc/kubeconfig/staging.yaml
        context: staging-context
        environment: staging
        region: us-west-1
        enabled: true
      - name: test-cluster
        kubeconfig_path: /etc/kubeconfig/test.yaml
        context: test-context
        environment: test
        region: us-west-1
        enabled: true

    scan_interval: 300
    domain_filter: .*\.yourcompany\.com$
    exclude_namespaces:
      - kube-system
      - kube-public
      - istio-system
    enable_istio: true
    enable_ingress: true
```

#### 4. Create Kubeconfig Secret (for external clusters)
```bash
# Create secret with kubeconfigs for external clusters
kubectl create secret generic cluster-kubeconfigs \
  --from-file=staging.yaml=/path/to/staging-kubeconfig \
  --from-file=test.yaml=/path/to/test-kubeconfig \
  -n ingressor-system
```

#### 5. Deploy Application
```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ingressor
  namespace: ingressor-system
  labels:
    app: ingressor
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ingressor
  template:
    metadata:
      labels:
        app: ingressor
    spec:
      serviceAccountName: ingressor
      containers:
      - name: ingressor
        image: ingressor:latest
        ports:
        - containerPort: 8000
          name: http
        env:
        - name: LOG_FORMAT
          value: "json"
        - name: LOG_LEVEL
          value: "INFO"
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 10
        volumeMounts:
        - name: config
          mountPath: /app/config.yaml
          subPath: config.yaml
          readOnly: true
        - name: kubeconfigs
          mountPath: /etc/kubeconfig
          readOnly: true
      volumes:
      - name: config
        configMap:
          name: ingressor-config
      - name: kubeconfigs
        secret:
          secretName: cluster-kubeconfigs
---
apiVersion: v1
kind: Service
metadata:
  name: ingressor
  namespace: ingressor-system
  labels:
    app: ingressor
spec:
  selector:
    app: ingressor
  ports:
  - name: http
    port: 80
    targetPort: 8000
  type: ClusterIP
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ingressor
  namespace: ingressor-system
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
spec:
  rules:
  - host: ingressor.yourcompany.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: ingressor
            port:
              number: 80
```

#### 6. Apply Resources
```bash
# Apply all resources
kubectl apply -f rbac.yaml
kubectl apply -f config-configmap.yaml
kubectl apply -f deployment.yaml

# Check deployment status
kubectl get pods -n ingressor-system
kubectl logs -f deployment/ingressor -n ingressor-system
```

## 🔄 Hybrid Deployment

You can mix deployment models for different use cases:

### Production Service + Development CLI
- **Production**: In-cluster deployment for continuous monitoring
- **Development**: CLI on laptops for testing and debugging

### Centralized Service + CI/CD Integration
- **Service**: External deployment on management server
- **CI/CD**: CLI commands in build pipelines

## 🛠️ Operational Patterns

### Development Workflow
```bash
# 1. Test configuration locally
ingressor validate-config --config config.yaml

# 2. Run one-time scan to verify connectivity
ingressor scan --config config.yaml --output table

# 3. Start development server with auto-reload
ingressor serve --config config.yaml --reload --verbose

# 4. Test API endpoints
curl http://localhost:8000/health
curl http://localhost:8000/domains
```

### CI/CD Integration
```yaml
# .github/workflows/domain-audit.yml
name: Domain Audit
on:
  schedule:
    - cron: '0 6 * * *'  # Daily at 6 AM
  workflow_dispatch:

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3

    - name: Setup Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.12'

    - name: Install Ingressor
      run: |
        pip install uv
        uv pip install -e .

    - name: Setup Kubeconfig
      run: |
        echo "${{ secrets.KUBECONFIG }}" | base64 -d > ~/.kube/config

    - name: Scan Domains
      run: |
        ingressor scan --config config.yaml --output json > domains.json

    - name: Upload Results
      uses: actions/upload-artifact@v3
      with:
        name: domain-scan-results
        path: domains.json
```

### Monitoring & Alerting
```bash
# Health check endpoint
curl -f http://ingressor.yourcompany.com/health

# Get summary statistics
curl http://ingressor.yourcompany.com/summary

# Trigger manual scan
curl -X POST http://ingressor.yourcompany.com/scan
```

## 🔧 Troubleshooting

### Common Issues

#### Authentication Errors
```bash
# Test cluster connectivity
kubectl get nodes --context=your-context

# Verify kubeconfig
ingressor validate-config --config config.yaml

# Check RBAC permissions (in-cluster)
kubectl auth can-i list ingresses --as=system:serviceaccount:ingressor-system:ingressor
```

#### Network Connectivity
```bash
# Test from pod (in-cluster deployment)
kubectl exec -it deployment/ingressor -n ingressor-system -- curl -k https://kubernetes.default.svc

# Check DNS resolution
kubectl exec -it deployment/ingressor -n ingressor-system -- nslookup kubernetes.default.svc
```

#### Configuration Issues
```bash
# Validate configuration syntax
ingressor validate-config --config config.yaml

# Test with verbose logging
ingressor --verbose scan --config config.yaml --output table
```

### Debug Commands
```bash
# Check logs (in-cluster)
kubectl logs -f deployment/ingressor -n ingressor-system

# Get detailed scan output
ingressor scan --config config.yaml --output json | jq '.'

# Test specific environment
ingressor scan --config config.yaml --environment prod --output table
```

## 📊 Best Practices

### Security
- **Principle of Least Privilege**: Grant minimal required RBAC permissions
- **Secret Management**: Store kubeconfigs as Kubernetes secrets, not in ConfigMaps
- **Network Policies**: Restrict network access where possible
- **Image Security**: Use specific image tags, not `latest`

### Performance
- **Resource Limits**: Set appropriate CPU/memory limits
- **Scan Intervals**: Balance freshness vs. API server load
- **Namespace Filtering**: Exclude unnecessary namespaces to reduce API calls
- **Domain Filtering**: Use regex filters to focus on relevant domains

### Reliability
- **Health Checks**: Configure proper liveness and readiness probes
- **Graceful Shutdown**: Allow time for in-flight requests to complete
- **Error Handling**: Monitor logs for authentication and network errors
- **Backup**: Keep configuration and kubeconfig backups

### Monitoring
- **Metrics**: Monitor scan duration, domain counts, and error rates
- **Alerting**: Set up alerts for scan failures or configuration changes
- **Logging**: Use structured JSON logging in production
- **Dashboards**: Create dashboards for domain trends and cluster health

## 🚀 Production Checklist

- [ ] RBAC permissions configured with least privilege
- [ ] Resource limits and requests defined
- [ ] Health checks configured
- [ ] Logging set to JSON format
- [ ] Monitoring and alerting in place
- [ ] Configuration validated and tested
- [ ] Kubeconfigs stored securely
- [ ] Network policies applied (if required)
- [ ] Backup strategy for configuration
- [ ] Documentation updated for your environment
