"""Tests for ingressor models."""

from datetime import datetime

import pytest
from pydantic import ValidationError

from ingressor.models import ClusterConfig, DomainInfo, DiscoveryConfig, ServiceSummary


class TestClusterConfig:
    """Tests for ClusterConfig model."""
    
    def test_valid_cluster_config(self):
        """Test creating a valid cluster configuration."""
        config = ClusterConfig(
            name="test-cluster",
            environment="test",
            kubeconfig_path="/path/to/config",
            context="test-context",
            region="us-west-1"
        )
        
        assert config.name == "test-cluster"
        assert config.environment == "test"
        assert config.enabled is True  # default value
    
    def test_minimal_cluster_config(self):
        """Test creating cluster config with minimal required fields."""
        config = ClusterConfig(
            name="minimal-cluster",
            environment="prod"
        )
        
        assert config.name == "minimal-cluster"
        assert config.environment == "prod"
        assert config.kubeconfig_path is None
        assert config.enabled is True
    
    def test_invalid_cluster_config(self):
        """Test validation errors for invalid cluster config."""
        with pytest.raises(ValidationError):
            ClusterConfig()  # missing required fields


class TestDomainInfo:
    """Tests for DomainInfo model."""
    
    def test_valid_domain_info(self):
        """Test creating valid domain information."""
        now = datetime.utcnow()
        domain = DomainInfo(
            domain="api.staging.tatari.dev",
            cluster="staging-cluster",
            environment="staging",
            namespace="default",
            resource_type="ingress",
            tls_enabled=True,
            discovered_at=now
        )
        
        assert domain.domain == "api.staging.tatari.dev"
        assert domain.cluster == "staging-cluster"
        assert domain.tls_enabled is True
        assert domain.discovered_at == now
    
    def test_domain_info_defaults(self):
        """Test default values for domain information."""
        domain = DomainInfo(
            domain="test.example.com",
            cluster="test-cluster",
            environment="test",
            namespace="default",
            resource_type="ingress"
        )
        
        assert domain.labels == {}
        assert domain.annotations == {}
        assert domain.tls_enabled is False
        assert isinstance(domain.discovered_at, datetime)
        assert isinstance(domain.last_seen, datetime)


class TestDiscoveryConfig:
    """Tests for DiscoveryConfig model."""
    
    def test_default_discovery_config(self):
        """Test default discovery configuration."""
        config = DiscoveryConfig()
        
        assert config.clusters == []
        assert config.scan_interval == 300
        assert config.domain_filter is None
        assert config.include_namespaces == []
        assert "kube-system" in config.exclude_namespaces
        assert config.enable_istio is True
        assert config.enable_ingress is True
    
    def test_custom_discovery_config(self):
        """Test custom discovery configuration."""
        cluster = ClusterConfig(name="test", environment="test")
        config = DiscoveryConfig(
            clusters=[cluster],
            scan_interval=600,
            domain_filter=r".*\.example\.com$",
            include_namespaces=["app", "api"],
            exclude_namespaces=["system"],
            enable_istio=False
        )
        
        assert len(config.clusters) == 1
        assert config.scan_interval == 600
        assert config.domain_filter == r".*\.example\.com$"
        assert config.include_namespaces == ["app", "api"]
        assert config.exclude_namespaces == ["system"]
        assert config.enable_istio is False


class TestServiceSummary:
    """Tests for ServiceSummary model."""
    
    def test_empty_service_summary(self):
        """Test empty service summary."""
        summary = ServiceSummary()
        
        assert summary.total_domains == 0
        assert summary.by_environment == {}
        assert summary.by_cluster == {}
        assert summary.by_namespace == {}
        assert summary.last_scan is None
    
    def test_populated_service_summary(self):
        """Test populated service summary."""
        now = datetime.utcnow()
        summary = ServiceSummary(
            total_domains=10,
            by_environment={"prod": 5, "staging": 3, "test": 2},
            by_cluster={"cluster-1": 6, "cluster-2": 4},
            by_namespace={"default": 8, "app": 2},
            last_scan=now
        )
        
        assert summary.total_domains == 10
        assert summary.by_environment["prod"] == 5
        assert summary.by_cluster["cluster-1"] == 6
        assert summary.by_namespace["default"] == 8
        assert summary.last_scan == now 