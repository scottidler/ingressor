"""Tests for core service discovery functionality."""

import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from kubernetes.client.rest import ApiException

from ingressor.core import IngressorClient, ServiceDiscovery
from ingressor.models import ClusterConfig, DiscoveryConfig, DomainInfo


class TestIngressorClient:
    """Tests for IngressorClient."""

    @pytest.fixture
    def cluster_config(self):
        """Create a test cluster configuration."""
        return ClusterConfig(
            name="test-cluster",
            environment="test",
            kubeconfig_path="/path/to/kubeconfig",
            context="test-context"
        )

    @pytest.fixture
    def client(self, cluster_config):
        """Create an IngressorClient instance."""
        return IngressorClient(cluster_config)

    def test_init(self, client, cluster_config):
        """Test IngressorClient initialization."""
        assert client.cluster_config == cluster_config
        assert client._k8s_client is None
        assert client._networking_v1 is None
        assert client._custom_objects is None

    @pytest.mark.asyncio
    @patch('ingressor.core.config.load_kube_config')
    @patch('ingressor.core.client.ApiClient')
    @patch('ingressor.core.client.NetworkingV1Api')
    @patch('ingressor.core.client.CustomObjectsApi')
    @pytest.mark.asyncio
    async def test_connect_with_kubeconfig(self, mock_custom, mock_networking,
                                         mock_api_client, mock_load_config, client):
        """Test connecting with kubeconfig file."""
        await client.connect()

        mock_load_config.assert_called_once_with(
            config_file="/path/to/kubeconfig",
            context="test-context"
        )
        mock_api_client.assert_called_once()
        mock_networking.assert_called_once()
        mock_custom.assert_called_once()

    @pytest.mark.asyncio
    @patch('ingressor.core.config.load_incluster_config')
    @patch('ingressor.core.client.ApiClient')
    @pytest.mark.asyncio
    async def test_connect_incluster(self, mock_api_client, mock_load_config):
        """Test connecting with in-cluster config."""
        cluster_config = ClusterConfig(
            name="test-cluster",
            environment="test",
            kubeconfig_path=None  # No kubeconfig path
        )
        client = IngressorClient(cluster_config)

        await client.connect()

        mock_load_config.assert_called_once()
        mock_api_client.assert_called_once()

    @pytest.mark.asyncio
    @patch('ingressor.core.config.load_kube_config')
    @pytest.mark.asyncio
    async def test_connect_failure(self, mock_load_config, client):
        """Test connection failure handling."""
        mock_load_config.side_effect = Exception("Connection failed")

        with pytest.raises(Exception, match="Connection failed"):
            await client.connect()

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_discover_ingress_domains_no_connection(self, client):
        """Test ingress discovery without connection calls connect."""
        with patch.object(client, 'connect') as mock_connect:
            mock_connect.return_value = None
            client._networking_v1 = None

            # Mock the networking API after connect
            mock_networking = MagicMock()
            mock_networking.list_ingress_for_all_namespaces.return_value.items = []

            async def set_networking(*args, **kwargs):
                client._networking_v1 = mock_networking

            mock_connect.side_effect = set_networking

            domains = await client.discover_ingress_domains()

            mock_connect.assert_called_once()
            assert domains == []

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_discover_ingress_domains_success(self, client):
        """Test successful ingress discovery."""
        # Mock Kubernetes API response
        mock_ingress = MagicMock()
        mock_ingress.metadata.name = "test-ingress"
        mock_ingress.metadata.namespace = "default"
        mock_ingress.metadata.labels = {"app": "test"}
        mock_ingress.metadata.annotations = {"nginx.ingress.kubernetes.io/ssl-redirect": "true"}
        mock_ingress.spec.rules = [MagicMock()]
        mock_ingress.spec.rules[0].host = "test.example.com"
        mock_ingress.spec.tls = [MagicMock()]
        mock_ingress.spec.tls[0].hosts = ["test.example.com"]

        mock_response = MagicMock()
        mock_response.items = [mock_ingress]

        mock_networking = MagicMock()
        mock_networking.list_ingress_for_all_namespaces.return_value = mock_response
        client._networking_v1 = mock_networking

        domains = await client.discover_ingress_domains()

        assert len(domains) == 1
        domain = domains[0]
        assert domain.domain == "test.example.com"
        assert domain.cluster == "test-cluster"
        assert domain.environment == "test"
        assert domain.namespace == "default"
        assert domain.ingress_name == "test-ingress"
        assert domain.resource_type == "ingress"
        assert domain.tls_enabled is True
        assert domain.labels == {"app": "test"}

    @pytest.mark.asyncio
    async def test_discover_ingress_domains_no_rules(self, client):
        """Test ingress discovery with no rules."""
        mock_ingress = MagicMock()
        mock_ingress.spec = None

        mock_response = MagicMock()
        mock_response.items = [mock_ingress]

        mock_networking = MagicMock()
        mock_networking.list_ingress_for_all_namespaces.return_value = mock_response
        client._networking_v1 = mock_networking

        domains = await client.discover_ingress_domains()
        assert domains == []

    @pytest.mark.asyncio
    async def test_discover_ingress_domains_no_host(self, client):
        """Test ingress discovery with no host."""
        mock_ingress = MagicMock()
        mock_ingress.spec.rules = [MagicMock()]
        mock_ingress.spec.rules[0].host = None

        mock_response = MagicMock()
        mock_response.items = [mock_ingress]

        mock_networking = MagicMock()
        mock_networking.list_ingress_for_all_namespaces.return_value = mock_response
        client._networking_v1 = mock_networking

        domains = await client.discover_ingress_domains()
        assert domains == []

    @pytest.mark.asyncio
    async def test_discover_ingress_domains_specific_namespaces(self, client):
        """Test ingress discovery in specific namespaces."""
        mock_ingress = MagicMock()
        mock_ingress.metadata.name = "test-ingress"
        mock_ingress.metadata.namespace = "app"
        mock_ingress.metadata.labels = {}
        mock_ingress.metadata.annotations = {}
        mock_ingress.spec.rules = [MagicMock()]
        mock_ingress.spec.rules[0].host = "app.example.com"
        mock_ingress.spec.tls = None

        mock_response = MagicMock()
        mock_response.items = [mock_ingress]

        mock_networking = MagicMock()
        mock_networking.list_namespaced_ingress.return_value = mock_response
        client._networking_v1 = mock_networking

        domains = await client.discover_ingress_domains(namespaces=["app"])

        assert len(domains) == 1
        assert domains[0].domain == "app.example.com"
        assert domains[0].namespace == "app"
        assert domains[0].tls_enabled is False
        mock_networking.list_namespaced_ingress.assert_called_once_with(namespace="app")

    @pytest.mark.asyncio
    async def test_discover_ingress_domains_api_exception(self, client):
        """Test ingress discovery with API exception."""
        mock_networking = MagicMock()
        mock_networking.list_namespaced_ingress.side_effect = ApiException(status=403, reason="Forbidden")
        client._networking_v1 = mock_networking

        domains = await client.discover_ingress_domains(namespaces=["forbidden"])
        assert domains == []

    @pytest.mark.asyncio
    async def test_discover_virtualservice_domains_success(self, client):
        """Test successful VirtualService discovery."""
        mock_vs_response = {
            "items": [
                {
                    "metadata": {
                        "name": "test-vs",
                        "namespace": "default",
                        "labels": {"app": "test"},
                        "annotations": {"istio.io/rev": "default"}
                    },
                    "spec": {
                        "hosts": ["api.example.com", "internal-service"],
                        "tls": [{"match": [{"sniHosts": ["api.example.com"]}]}]
                    }
                }
            ]
        }

        mock_custom = MagicMock()
        mock_custom.list_cluster_custom_object.return_value = mock_vs_response
        client._custom_objects = mock_custom

        domains = await client.discover_virtualservice_domains()

        assert len(domains) == 1  # Only external domain, not internal-service
        domain = domains[0]
        assert domain.domain == "api.example.com"
        assert domain.cluster == "test-cluster"
        assert domain.environment == "test"
        assert domain.namespace == "default"
        assert domain.service_name == "test-vs"
        assert domain.resource_type == "virtualservice"
        assert domain.tls_enabled is True

    @pytest.mark.asyncio
    async def test_discover_virtualservice_domains_no_external_hosts(self, client):
        """Test VirtualService discovery with no external hosts."""
        mock_vs_response = {
            "items": [
                {
                    "metadata": {"name": "test-vs", "namespace": "default"},
                    "spec": {
                        "hosts": ["internal-service", "another.local"]  # No external domains
                    }
                }
            ]
        }

        mock_custom = MagicMock()
        mock_custom.list_cluster_custom_object.return_value = mock_vs_response
        client._custom_objects = mock_custom

        domains = await client.discover_virtualservice_domains()
        assert domains == []

    @pytest.mark.asyncio
    async def test_discover_virtualservice_domains_specific_namespaces(self, client):
        """Test VirtualService discovery in specific namespaces."""
        mock_vs_response = {
            "items": [
                {
                    "metadata": {"name": "test-vs", "namespace": "app"},
                    "spec": {"hosts": ["app.example.com"]}
                }
            ]
        }

        mock_custom = MagicMock()
        mock_custom.list_namespaced_custom_object.return_value = mock_vs_response
        client._custom_objects = mock_custom

        domains = await client.discover_virtualservice_domains(namespaces=["app"])

        assert len(domains) == 1
        assert domains[0].domain == "app.example.com"
        mock_custom.list_namespaced_custom_object.assert_called_once_with(
            group="networking.istio.io",
            version="v1beta1",
            namespace="app",
            plural="virtualservices"
        )

    @pytest.mark.asyncio
    async def test_disconnect(self, client):
        """Test client disconnect."""
        mock_k8s_client = AsyncMock()
        client._k8s_client = mock_k8s_client

        await client.disconnect()
        mock_k8s_client.close.assert_called_once()


class TestServiceDiscovery:
    """Tests for ServiceDiscovery."""

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

    @pytest.fixture
    def service_discovery(self, discovery_config):
        """Create a ServiceDiscovery instance."""
        return ServiceDiscovery(discovery_config)

    def test_init(self, service_discovery, discovery_config):
        """Test ServiceDiscovery initialization."""
        assert service_discovery.config == discovery_config
        assert service_discovery.domains == {}
        assert service_discovery.last_scan is None

    @patch('ingressor.core.IngressorClient')
    @pytest.mark.asyncio
    async def test_scan_cluster_success(self, mock_client_class, service_discovery):
        """Test successful cluster scanning."""
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

        cluster_config = service_discovery.config.clusters[0]
        domains = await service_discovery._scan_cluster(cluster_config)

        assert len(domains) == 2
        assert domains[0].domain == "test.example.com"
        assert domains[1].domain == "api.example.com"

        mock_client.connect.assert_called_once()
        mock_client.discover_ingress_domains.assert_called_once()
        mock_client.discover_virtualservice_domains.assert_called_once()
        mock_client.disconnect.assert_called_once()

    @patch('ingressor.core.IngressorClient')
    @pytest.mark.asyncio
    async def test_scan_cluster_with_domain_filter(self, mock_client_class, service_discovery):
        """Test cluster scanning with domain filtering."""
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

        cluster_config = service_discovery.config.clusters[0]
        domains = await service_discovery._scan_cluster(cluster_config)

        # Only the domain matching the filter should be returned
        assert len(domains) == 1
        assert domains[0].domain == "test.example.com"

    @patch('ingressor.core.IngressorClient')
    @pytest.mark.asyncio
    async def test_scan_cluster_exclude_namespaces(self, mock_client_class, service_discovery):
        """Test cluster scanning with namespace exclusion."""
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

        cluster_config = service_discovery.config.clusters[0]
        domains = await service_discovery._scan_cluster(cluster_config)

        # Only the domain not in excluded namespace should be returned
        assert len(domains) == 1
        assert domains[0].domain == "test.example.com"
        assert domains[0].namespace == "default"

    @patch('ingressor.core.IngressorClient')
    @pytest.mark.asyncio
    async def test_scan_cluster_exception(self, mock_client_class, service_discovery):
        """Test cluster scanning with exception."""
        mock_client = AsyncMock()
        mock_client.connect.side_effect = Exception("Connection failed")
        mock_client_class.return_value = mock_client

        cluster_config = service_discovery.config.clusters[0]
        domains = await service_discovery._scan_cluster(cluster_config)

        # Should return empty list on exception
        assert domains == []
        mock_client.disconnect.assert_called_once()

    @patch('ingressor.core.ServiceDiscovery._scan_cluster')
    @pytest.mark.asyncio
    async def test_scan_all_clusters(self, mock_scan_cluster, service_discovery):
        """Test scanning all clusters."""
        # Mock scan results for enabled clusters
        mock_scan_cluster.side_effect = [
            [DomainInfo(domain="test1.example.com", cluster="cluster1", environment="test", namespace="default", resource_type="ingress")],
            [DomainInfo(domain="test2.example.com", cluster="cluster2", environment="prod", namespace="default", resource_type="ingress")]
        ]

        domains = await service_discovery.scan_all_clusters()

        # Should scan only enabled clusters (cluster1 and cluster2, not cluster3)
        assert len(domains) == 2
        assert mock_scan_cluster.call_count == 2

        # Check internal storage
        assert len(service_discovery.domains) == 2
        assert "test1.example.com" in service_discovery.domains
        assert "test2.example.com" in service_discovery.domains
        assert service_discovery.last_scan is not None

    def test_get_domains_no_filter(self, service_discovery):
        """Test getting domains without filters."""
        # Add some test domains
        service_discovery.domains = {
            "test1.example.com": DomainInfo(domain="test1.example.com", cluster="cluster1", environment="test", namespace="default", resource_type="ingress"),
            "test2.example.com": DomainInfo(domain="test2.example.com", cluster="cluster2", environment="prod", namespace="api", resource_type="ingress")
        }

        domains = service_discovery.get_domains()
        assert len(domains) == 2
        # Should be sorted by domain name
        assert domains[0].domain == "test1.example.com"
        assert domains[1].domain == "test2.example.com"

    def test_get_domains_with_filters(self, service_discovery):
        """Test getting domains with filters."""
        service_discovery.domains = {
            "test1.example.com": DomainInfo(domain="test1.example.com", cluster="cluster1", environment="test", namespace="default", resource_type="ingress"),
            "test2.example.com": DomainInfo(domain="test2.example.com", cluster="cluster2", environment="prod", namespace="api", resource_type="ingress"),
            "test3.example.com": DomainInfo(domain="test3.example.com", cluster="cluster1", environment="test", namespace="web", resource_type="ingress")
        }

        # Filter by environment
        domains = service_discovery.get_domains(environment="test")
        assert len(domains) == 2
        assert all(d.environment == "test" for d in domains)

        # Filter by cluster
        domains = service_discovery.get_domains(cluster="cluster2")
        assert len(domains) == 1
        assert domains[0].cluster == "cluster2"

        # Filter by namespace
        domains = service_discovery.get_domains(namespace="api")
        assert len(domains) == 1
        assert domains[0].namespace == "api"

        # Multiple filters
        domains = service_discovery.get_domains(environment="test", cluster="cluster1")
        assert len(domains) == 2
        assert all(d.environment == "test" and d.cluster == "cluster1" for d in domains)

    def test_get_summary(self, service_discovery):
        """Test getting service summary."""
        service_discovery.domains = {
            "test1.example.com": DomainInfo(domain="test1.example.com", cluster="cluster1", environment="test", namespace="default", resource_type="ingress"),
            "test2.example.com": DomainInfo(domain="test2.example.com", cluster="cluster2", environment="prod", namespace="api", resource_type="ingress"),
            "test3.example.com": DomainInfo(domain="test3.example.com", cluster="cluster1", environment="test", namespace="web", resource_type="ingress")
        }
        service_discovery.last_scan = datetime(2023, 1, 1, 12, 0, 0)

        summary = service_discovery.get_summary()

        assert summary.total_domains == 3
        assert summary.by_environment == {"test": 2, "prod": 1}
        assert summary.by_cluster == {"cluster1": 2, "cluster2": 1}
        assert summary.by_namespace == {"default": 1, "api": 1, "web": 1}
        assert summary.last_scan == datetime(2023, 1, 1, 12, 0, 0)
