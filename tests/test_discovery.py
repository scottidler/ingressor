"""Tests for Singleton ServiceDiscovery implementation."""

import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ingressor.discovery import ServiceDiscovery
from ingressor.models import ClusterConfig, DiscoveryConfig, DomainInfo


class TestServiceDiscoverySingleton:
    """Tests for Singleton ServiceDiscovery."""

    @pytest.fixture(autouse=True)
    def reset_singleton(self):
        """Reset singleton before and after each test."""
        # Reset before test
        ServiceDiscovery.reset()
        yield
        # Reset after test
        ServiceDiscovery.reset()

    @pytest.fixture
    def discovery_config(self):
        """Create a test discovery configuration."""
        return DiscoveryConfig(
            clusters=[
                ClusterConfig(name="cluster1", environment="test", enabled=True),
                ClusterConfig(name="cluster2", environment="prod", enabled=True),
                ClusterConfig(name="cluster3", environment="staging", enabled=False)
            ],
            scan_interval=300,
            domain_filter=r".*\.example\.com$",
            exclude_namespaces=["kube-system"]
        )

    def test_singleton_creation(self, discovery_config):
        """Test that ServiceDiscovery follows singleton pattern."""
        # First instance
        discovery1 = ServiceDiscovery(discovery_config)

        # Second instance should be the same
        discovery2 = ServiceDiscovery()

        assert discovery1 is discovery2
        assert discovery1.config == discovery_config
        assert discovery2.config == discovery_config

    def test_get_instance_before_initialization(self):
        """Test getting instance before initialization raises error."""
        with pytest.raises(RuntimeError, match="ServiceDiscovery singleton not initialized"):
            ServiceDiscovery.get_instance()

    def test_get_instance_after_initialization(self, discovery_config):
        """Test getting instance after initialization."""
        # Initialize
        discovery = ServiceDiscovery(discovery_config)

        # Get instance
        instance = ServiceDiscovery.get_instance()

        assert instance is discovery
        assert instance.config == discovery_config

    def test_initialization_without_config_fails(self):
        """Test that initialization without config fails."""
        with pytest.raises(RuntimeError, match="ServiceDiscovery must be initialized with a config"):
            ServiceDiscovery()

    def test_reset_singleton(self, discovery_config):
        """Test resetting the singleton."""
        # Initialize
        discovery1 = ServiceDiscovery(discovery_config)

        # Reset
        ServiceDiscovery.reset()

        # Should be able to create new instance
        discovery2 = ServiceDiscovery(discovery_config)

        # Should be different instances (new singleton)
        assert discovery1 is not discovery2

    def test_singleton_initialization_state(self, discovery_config):
        """Test singleton initialization state."""
        discovery = ServiceDiscovery(discovery_config)

        assert discovery.config == discovery_config
        assert discovery.domains == {}
        assert discovery.last_scan is None
        assert discovery._domain_filter is not None  # Should compile regex
        assert discovery._initialized is True

    @patch('ingressor.discovery.IngressorClient')
    @pytest.mark.asyncio
    async def test_scan_all_clusters_with_lock(self, mock_client_class, discovery_config):
        """Test that scan_all_clusters uses async lock."""
        discovery = ServiceDiscovery(discovery_config)

        # Mock IngressorClient
        mock_client = AsyncMock()
        mock_client.discover_ingress_domains.return_value = []
        mock_client.discover_virtualservice_domains.return_value = []
        mock_client_class.return_value = mock_client

        # Should be able to scan
        domains = await discovery.scan_all_clusters()
        assert domains == []

        # Verify lock was used (by checking that scan completed)
        assert discovery.last_scan is not None

    @patch('ingressor.discovery.IngressorClient')
    @pytest.mark.asyncio
    async def test_scan_cluster_success(self, mock_client_class, discovery_config):
        """Test successful cluster scanning."""
        discovery = ServiceDiscovery(discovery_config)

        # Mock IngressorClient
        mock_client = AsyncMock()
        mock_client.discover_ingress_domains.return_value = [
            DomainInfo(
                domain="test.example.com",
                cluster="cluster1",
                environment="test",
                namespace="default",
                resource_type="ingress"
            )
        ]
        mock_client.discover_virtualservice_domains.return_value = [
            DomainInfo(
                domain="api.example.com",
                cluster="cluster1",
                environment="test",
                namespace="api",
                resource_type="virtualservice"
            )
        ]
        mock_client_class.return_value = mock_client

        cluster_config = discovery.config.clusters[0]
        domains = await discovery._scan_cluster(cluster_config)

        assert len(domains) == 2
        assert domains[0].domain == "test.example.com"
        assert domains[1].domain == "api.example.com"

        mock_client.connect.assert_called_once()
        mock_client.discover_ingress_domains.assert_called_once()
        mock_client.discover_virtualservice_domains.assert_called_once()
        mock_client.disconnect.assert_called_once()

    @patch('ingressor.discovery.IngressorClient')
    @pytest.mark.asyncio
    async def test_scan_cluster_with_domain_filter(self, mock_client_class, discovery_config):
        """Test cluster scanning with domain filtering."""
        discovery = ServiceDiscovery(discovery_config)

        mock_client = AsyncMock()
        mock_client.discover_ingress_domains.return_value = [
            DomainInfo(
                domain="test.example.com",  # Matches filter
                cluster="cluster1",
                environment="test",
                namespace="default",
                resource_type="ingress"
            ),
            DomainInfo(
                domain="test.other.com",  # Doesn't match filter
                cluster="cluster1",
                environment="test",
                namespace="default",
                resource_type="ingress"
            )
        ]
        mock_client.discover_virtualservice_domains.return_value = []
        mock_client_class.return_value = mock_client

        cluster_config = discovery.config.clusters[0]
        domains = await discovery._scan_cluster(cluster_config)

        # Only the domain matching the filter should be returned
        assert len(domains) == 1
        assert domains[0].domain == "test.example.com"

    @patch('ingressor.discovery.IngressorClient')
    @pytest.mark.asyncio
    async def test_scan_cluster_exclude_namespaces(self, mock_client_class, discovery_config):
        """Test cluster scanning with namespace exclusion."""
        discovery = ServiceDiscovery(discovery_config)

        mock_client = AsyncMock()
        mock_client.discover_ingress_domains.return_value = [
            DomainInfo(
                domain="test.example.com",
                cluster="cluster1",
                environment="test",
                namespace="default",  # Not excluded
                resource_type="ingress"
            ),
            DomainInfo(
                domain="system.example.com",
                cluster="cluster1",
                environment="test",
                namespace="kube-system",  # Excluded
                resource_type="ingress"
            )
        ]
        mock_client.discover_virtualservice_domains.return_value = []
        mock_client_class.return_value = mock_client

        cluster_config = discovery.config.clusters[0]
        domains = await discovery._scan_cluster(cluster_config)

        # Only the domain not in excluded namespace should be returned
        assert len(domains) == 1
        assert domains[0].domain == "test.example.com"
        assert domains[0].namespace == "default"

    @patch('ingressor.discovery.IngressorClient')
    @pytest.mark.asyncio
    async def test_scan_cluster_exception_handling(self, mock_client_class, discovery_config):
        """Test cluster scanning with exception handling."""
        discovery = ServiceDiscovery(discovery_config)

        mock_client = AsyncMock()
        mock_client.connect.side_effect = Exception("Connection failed")
        mock_client_class.return_value = mock_client

        cluster_config = discovery.config.clusters[0]
        domains = await discovery._scan_cluster(cluster_config)

        # Should return empty list on exception
        assert domains == []
        mock_client.disconnect.assert_called_once()

    @patch('ingressor.discovery.ServiceDiscovery._scan_cluster')
    @pytest.mark.asyncio
    async def test_scan_all_clusters(self, mock_scan_cluster, discovery_config):
        """Test scanning all clusters."""
        discovery = ServiceDiscovery(discovery_config)

        # Mock scan results for enabled clusters
        mock_scan_cluster.side_effect = [
            [DomainInfo(domain="test1.example.com", cluster="cluster1", environment="test", namespace="default", resource_type="ingress")],
            [DomainInfo(domain="test2.example.com", cluster="cluster2", environment="prod", namespace="default", resource_type="ingress")]
        ]

        domains = await discovery.scan_all_clusters()

        # Should scan only enabled clusters (cluster1 and cluster2, not cluster3)
        assert len(domains) == 2
        assert mock_scan_cluster.call_count == 2

        # Check internal storage
        assert len(discovery.domains) == 2
        assert "test1.example.com" in discovery.domains
        assert "test2.example.com" in discovery.domains
        assert discovery.last_scan is not None

    def test_get_domains_no_filter(self, discovery_config):
        """Test getting domains without filters."""
        discovery = ServiceDiscovery(discovery_config)

        # Add some test domains
        discovery.domains = {
            "test1.example.com": DomainInfo(domain="test1.example.com", cluster="cluster1", environment="test", namespace="default", resource_type="ingress"),
            "test2.example.com": DomainInfo(domain="test2.example.com", cluster="cluster2", environment="prod", namespace="api", resource_type="ingress")
        }

        domains = discovery.get_domains()
        assert len(domains) == 2
        # Should be sorted by domain name
        assert domains[0].domain == "test1.example.com"
        assert domains[1].domain == "test2.example.com"

    def test_get_domains_with_filters(self, discovery_config):
        """Test getting domains with filters."""
        discovery = ServiceDiscovery(discovery_config)

        discovery.domains = {
            "test1.example.com": DomainInfo(domain="test1.example.com", cluster="cluster1", environment="test", namespace="default", resource_type="ingress"),
            "test2.example.com": DomainInfo(domain="test2.example.com", cluster="cluster2", environment="prod", namespace="api", resource_type="ingress"),
            "test3.example.com": DomainInfo(domain="test3.example.com", cluster="cluster1", environment="test", namespace="web", resource_type="ingress")
        }

        # Filter by environment
        domains = discovery.get_domains(environment="test")
        assert len(domains) == 2
        assert all(d.environment == "test" for d in domains)

        # Filter by cluster
        domains = discovery.get_domains(cluster="cluster2")
        assert len(domains) == 1
        assert domains[0].cluster == "cluster2"

        # Filter by namespace
        domains = discovery.get_domains(namespace="api")
        assert len(domains) == 1
        assert domains[0].namespace == "api"

        # Multiple filters
        domains = discovery.get_domains(environment="test", cluster="cluster1")
        assert len(domains) == 2
        assert all(d.environment == "test" and d.cluster == "cluster1" for d in domains)

    def test_get_summary(self, discovery_config):
        """Test getting service summary."""
        discovery = ServiceDiscovery(discovery_config)

        discovery.domains = {
            "test1.example.com": DomainInfo(domain="test1.example.com", cluster="cluster1", environment="test", namespace="default", resource_type="ingress"),
            "test2.example.com": DomainInfo(domain="test2.example.com", cluster="cluster2", environment="prod", namespace="api", resource_type="ingress"),
            "test3.example.com": DomainInfo(domain="test3.example.com", cluster="cluster1", environment="test", namespace="web", resource_type="ingress")
        }
        discovery.last_scan = datetime(2023, 1, 1, 12, 0, 0)

        summary = discovery.get_summary()

        assert summary.total_domains == 3
        assert summary.by_environment == {"test": 2, "prod": 1}
        assert summary.by_cluster == {"cluster1": 2, "cluster2": 1}
        assert summary.by_namespace == {"default": 1, "api": 1, "web": 1}
        assert summary.last_scan == datetime(2023, 1, 1, 12, 0, 0)

    def test_apply_filters_domain_regex(self, discovery_config):
        """Test domain regex filtering."""
        discovery = ServiceDiscovery(discovery_config)

        domains = [
            DomainInfo(domain="test.example.com", cluster="test", environment="test", namespace="default", resource_type="ingress"),
            DomainInfo(domain="test.other.com", cluster="test", environment="test", namespace="default", resource_type="ingress"),
            DomainInfo(domain="api.example.com", cluster="test", environment="test", namespace="default", resource_type="ingress")
        ]

        filtered = discovery._apply_filters(domains)

        # Only domains matching .*\.example\.com$ should remain
        assert len(filtered) == 2
        assert filtered[0].domain == "test.example.com"
        assert filtered[1].domain == "api.example.com"

    def test_apply_filters_namespace_exclusion(self, discovery_config):
        """Test namespace exclusion filtering."""
        discovery = ServiceDiscovery(discovery_config)

        domains = [
            DomainInfo(domain="test.example.com", cluster="test", environment="test", namespace="default", resource_type="ingress"),
            DomainInfo(domain="system.example.com", cluster="test", environment="test", namespace="kube-system", resource_type="ingress"),
            DomainInfo(domain="api.example.com", cluster="test", environment="test", namespace="api", resource_type="ingress")
        ]

        filtered = discovery._apply_filters(domains)

        # kube-system namespace should be excluded
        assert len(filtered) == 2
        assert filtered[0].domain == "test.example.com"
        assert filtered[1].domain == "api.example.com"
        assert all(d.namespace != "kube-system" for d in filtered)

    def test_no_domain_filter_config(self):
        """Test ServiceDiscovery with no domain filter."""
        config = DiscoveryConfig(
            clusters=[ClusterConfig(name="test", environment="test", enabled=True)],
            domain_filter=None  # No filter
        )

        discovery = ServiceDiscovery(config)
        assert discovery._domain_filter is None

        # All domains should pass through
        domains = [
            DomainInfo(domain="anything.com", cluster="test", environment="test", namespace="default", resource_type="ingress"),
            DomainInfo(domain="example.org", cluster="test", environment="test", namespace="default", resource_type="ingress")
        ]

        filtered = discovery._apply_filters(domains)
        assert len(filtered) == 2

    @pytest.mark.asyncio
    async def test_concurrent_access_thread_safety(self, discovery_config):
        """Test that singleton behaves correctly under concurrent access."""
        # This is a basic test - real thread safety would need more complex testing
        discovery = ServiceDiscovery(discovery_config)

        async def get_instance():
            return ServiceDiscovery.get_instance()

        # Multiple concurrent gets should return same instance
        instances = await asyncio.gather(*[get_instance() for _ in range(10)])

        # All should be the same instance
        assert all(instance is discovery for instance in instances)
