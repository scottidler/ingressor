"""Tests for FastAPI REST API endpoints."""

import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from httpx import AsyncClient

from ingressor.api import app, initialize_discovery, get_discovery
from ingressor.core import ServiceDiscovery
from ingressor.models import ClusterConfig, DiscoveryConfig, DomainInfo, ServiceSummary


class TestAPI:
    """Tests for FastAPI endpoints."""

    @pytest.fixture
    def client(self):
        """Create a test client."""
        return TestClient(app)

    def setup_mock_discovery(self, mock_get_discovery, mock_discovery):
        """Helper to setup async mock discovery."""
        async def mock_get_disc():
            return mock_discovery
        mock_get_discovery.side_effect = mock_get_disc

    @pytest.fixture
    def mock_discovery_config(self):
        """Create a mock discovery configuration."""
        return DiscoveryConfig(
            clusters=[
                ClusterConfig(name="test-cluster", environment="test", enabled=True)
            ],
            scan_interval=300,
            domain_filter=r".*\.example\.com$"
        )

    @pytest.fixture
    def mock_domains(self):
        """Create mock domain data."""
        return [
            DomainInfo(
                domain="api.test.example.com",
                cluster="test-cluster",
                environment="test",
                namespace="api",
                resource_type="ingress",
                tls_enabled=True
            ),
            DomainInfo(
                domain="web.test.example.com",
                cluster="test-cluster",
                environment="test",
                namespace="web",
                resource_type="virtualservice",
                tls_enabled=False
            )
        ]

    @pytest.fixture
    def mock_summary(self):
        """Create mock service summary."""
        return ServiceSummary(
            total_domains=2,
            by_environment={"test": 2},
            by_cluster={"test-cluster": 2},
            by_namespace={"api": 1, "web": 1},
            last_scan=datetime(2023, 1, 1, 12, 0, 0)
        )

    def test_health_check(self, client):
        """Test health check endpoint."""
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "healthy", "service": "ingressor"}

    def test_initialize_discovery(self, mock_discovery_config):
        """Test discovery initialization."""
        initialize_discovery(mock_discovery_config)

        # Verify global discovery instance is set
        discovery = asyncio.run(get_discovery())
        assert isinstance(discovery, ServiceDiscovery)
        assert discovery.config == mock_discovery_config

    @patch('ingressor.api.get_discovery')
    def test_get_domains_no_filter(self, mock_get_discovery, client, mock_domains):
        """Test getting all domains without filters."""
        mock_discovery = MagicMock()
        mock_discovery.get_domains.return_value = mock_domains
        self.setup_mock_discovery(mock_get_discovery, mock_discovery)

        response = client.get("/domains")

        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2
        assert data[0]["domain"] == "api.test.example.com"
        assert data[1]["domain"] == "web.test.example.com"

        mock_discovery.get_domains.assert_called_once_with(
            environment=None,
            cluster=None,
            namespace=None
        )

    @patch('ingressor.api.get_discovery')
    def test_get_domains_with_filters(self, mock_get_discovery, client, mock_domains):
        """Test getting domains with filters."""
        mock_discovery = MagicMock()
        mock_discovery.get_domains.return_value = [mock_domains[0]]  # Only first domain
        self.setup_mock_discovery(mock_get_discovery, mock_discovery)

        response = client.get("/domains?environment=test&cluster=test-cluster&namespace=api")

        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["domain"] == "api.test.example.com"

        mock_discovery.get_domains.assert_called_once_with(
            environment="test",
            cluster="test-cluster",
            namespace="api"
        )

    @patch('ingressor.api.get_discovery')
    def test_get_domain_by_name_success(self, mock_get_discovery, client, mock_domains):
        """Test getting a specific domain by name."""
        mock_discovery = MagicMock()
        mock_discovery.domains = {"api.test.example.com": mock_domains[0]}
        self.setup_mock_discovery(mock_get_discovery, mock_discovery)

        response = client.get("/domains/api.test.example.com")

        assert response.status_code == 200
        data = response.json()
        assert data["domain"] == "api.test.example.com"
        assert data["cluster"] == "test-cluster"

    @patch('ingressor.api.get_discovery')
    def test_get_domain_by_name_not_found(self, mock_get_discovery, client):
        """Test getting a non-existent domain."""
        mock_discovery = MagicMock()
        mock_discovery.domains = {}
        self.setup_mock_discovery(mock_get_discovery, mock_discovery)

        response = client.get("/domains/nonexistent.example.com")

        assert response.status_code == 404
        assert "not found" in response.json()["detail"]

    @patch('ingressor.api.get_discovery')
    def test_get_summary(self, mock_get_discovery, client, mock_summary):
        """Test getting service summary."""
        mock_discovery = MagicMock()
        mock_discovery.get_summary.return_value = mock_summary
        self.setup_mock_discovery(mock_get_discovery, mock_discovery)

        response = client.get("/summary")

        assert response.status_code == 200
        data = response.json()
        assert data["total_domains"] == 2
        assert data["by_environment"] == {"test": 2}
        assert data["by_cluster"] == {"test-cluster": 2}

    @patch('ingressor.api.get_discovery')
    def test_get_environments(self, mock_get_discovery, client, mock_summary):
        """Test getting list of environments."""
        mock_discovery = MagicMock()
        mock_discovery.get_summary.return_value = mock_summary
        self.setup_mock_discovery(mock_get_discovery, mock_discovery)

        response = client.get("/environments")

        assert response.status_code == 200
        data = response.json()
        assert data["environments"] == ["test"]

    @patch('ingressor.api.get_discovery')
    def test_get_clusters(self, mock_get_discovery, client, mock_summary):
        """Test getting list of clusters."""
        mock_discovery = MagicMock()
        mock_discovery.get_summary.return_value = mock_summary
        self.setup_mock_discovery(mock_get_discovery, mock_discovery)

        response = client.get("/clusters")

        assert response.status_code == 200
        data = response.json()
        assert data["clusters"] == ["test-cluster"]

    @patch('ingressor.api.get_discovery')
    def test_get_namespaces(self, mock_get_discovery, client, mock_summary):
        """Test getting list of namespaces."""
        mock_discovery = MagicMock()
        mock_discovery.get_summary.return_value = mock_summary
        self.setup_mock_discovery(mock_get_discovery, mock_discovery)

        response = client.get("/namespaces")

        assert response.status_code == 200
        data = response.json()
        assert data["namespaces"] == ["api", "web"]

    @patch('ingressor.api.get_discovery')
    def test_trigger_scan_success(self, mock_get_discovery, client, mock_domains):
        """Test manually triggering a scan."""
        mock_discovery = MagicMock()
        mock_discovery.scan_all_clusters = AsyncMock(return_value=mock_domains)
        self.setup_mock_discovery(mock_get_discovery, mock_discovery)

        response = client.post("/scan")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["domains_count"] == 2
        assert "Scan completed" in data["message"]

        mock_discovery.scan_all_clusters.assert_called_once()

    @patch('ingressor.api.get_discovery')
    def test_trigger_scan_failure(self, mock_get_discovery, client):
        """Test manual scan failure."""
        mock_discovery = MagicMock()
        mock_discovery.scan_all_clusters = AsyncMock(side_effect=Exception("Scan failed"))
        self.setup_mock_discovery(mock_get_discovery, mock_discovery)

        response = client.post("/scan")

        assert response.status_code == 500
        assert "Scan failed" in response.json()["detail"]

    @patch('ingressor.api.get_discovery')
    def test_get_config(self, mock_get_discovery, client, mock_discovery_config):
        """Test getting sanitized configuration."""
        mock_discovery = MagicMock()
        mock_discovery.config = mock_discovery_config
        self.setup_mock_discovery(mock_get_discovery, mock_discovery)

        response = client.get("/config")

        assert response.status_code == 200
        data = response.json()
        assert "clusters" in data
        assert data["scan_interval"] == 300
        assert data["domain_filter"] == r".*\.example\.com$"

    @patch('ingressor.api.get_discovery')
    def test_get_config_sanitizes_kubeconfig_paths(self, mock_get_discovery, client):
        """Test that kubeconfig paths are sanitized in config response."""
        config_with_path = DiscoveryConfig(
            clusters=[
                ClusterConfig(
                    name="test-cluster",
                    environment="test",
                    kubeconfig_path="/secret/path/to/kubeconfig",
                    enabled=True
                )
            ]
        )

        mock_discovery = MagicMock()
        mock_discovery.config = config_with_path
        self.setup_mock_discovery(mock_get_discovery, mock_discovery)

        response = client.get("/config")

        assert response.status_code == 200
        data = response.json()
        # Kubeconfig path should be sanitized
        assert data["clusters"][0]["kubeconfig_path"] == "***"


    def test_get_discovery_not_initialized(self, client):
        """Test endpoints when discovery is not initialized."""
        # Clear global discovery
        import ingressor.api
        ingressor.api.discovery = None

        response = client.get("/domains")
        assert response.status_code == 503
        assert "not initialized" in response.json()["detail"]


class TestRequestLoggingMiddleware:
    """Tests for request logging middleware."""

    @pytest.fixture
    def client(self):
        """Create a test client."""
        return TestClient(app)

    @patch('ingressor.api.log_api_request')
    @patch('ingressor.api.log_api_response')
    def test_request_logging_middleware(self, mock_log_response, mock_log_request, client):
        """Test that requests are logged by middleware."""
        response = client.get("/health")

        assert response.status_code == 200

        # Verify request was logged
        mock_log_request.assert_called_once()
        args = mock_log_request.call_args[0]
        assert args[1] == "GET"  # method
        assert args[2] == "/health"  # path

        # Verify response was logged
        mock_log_response.assert_called_once()
        args = mock_log_response.call_args[0]
        assert args[1] == "GET"  # method
        assert args[2] == "/health"  # path
        assert args[3] == 200  # status code


@pytest.mark.asyncio
class TestAsyncAPI:
    """Tests for async API functionality."""

    @pytest.fixture
    def mock_discovery_config(self):
        """Create a mock discovery configuration."""
        return DiscoveryConfig(
            clusters=[
                ClusterConfig(name="test-cluster", environment="test", enabled=True)
            ]
        )

    async def test_periodic_scan_success(self, mock_discovery_config):
        """Test periodic scan background task."""
        with patch('ingressor.api.discovery') as mock_discovery:
            mock_discovery.scan_all_clusters.return_value = []
            mock_discovery.config.scan_interval = 1  # Short interval for testing

            from ingressor.api import periodic_scan

            # Run periodic scan for a short time
            task = asyncio.create_task(periodic_scan())
            await asyncio.sleep(0.1)  # Let it run briefly
            task.cancel()

            try:
                await task
            except asyncio.CancelledError:
                pass

            # Should have attempted at least one scan
            mock_discovery.scan_all_clusters.assert_called()

    async def test_periodic_scan_no_discovery(self):
        """Test periodic scan when discovery is not initialized."""
        with patch('ingressor.api.discovery', None):
            from ingressor.api import periodic_scan

            # Run periodic scan for a short time
            task = asyncio.create_task(periodic_scan())
            await asyncio.sleep(0.1)  # Let it run briefly
            task.cancel()

            try:
                await task
            except asyncio.CancelledError:
                pass

            # Should handle None discovery gracefully
            # (No assertions needed, just shouldn't crash)

    async def test_periodic_scan_exception_handling(self, mock_discovery_config):
        """Test periodic scan exception handling."""
        with patch('ingressor.api.discovery') as mock_discovery:
            mock_discovery.scan_all_clusters.side_effect = Exception("Scan failed")
            mock_discovery.config.scan_interval = 1

            from ingressor.api import periodic_scan

            # Run periodic scan for a short time
            task = asyncio.create_task(periodic_scan())
            await asyncio.sleep(0.1)  # Let it run briefly
            task.cancel()

            try:
                await task
            except asyncio.CancelledError:
                pass

            # Should have attempted scan and handled exception
            mock_discovery.scan_all_clusters.assert_called()
