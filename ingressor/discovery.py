"""Singleton ServiceDiscovery implementation for ingressor."""

import asyncio
import re
from datetime import datetime
from typing import Dict, List, Optional

from .ingressor import IngressorClient
from .logging_config import get_logger, log_discovery_event, log_function_entry, log_function_exit
from .models import ClusterConfig, DiscoveryConfig, DomainInfo, ServiceSummary


class ServiceDiscovery:
    """Singleton service discovery manager for multi-cluster Kubernetes environments.

    This class implements the Singleton pattern to ensure only one instance
    manages the discovery process across all clusters and maintains shared state.
    """

    _instance: Optional['ServiceDiscovery'] = None
    _initialized: bool = False
    _lock = asyncio.Lock()

    def __new__(cls, config: Optional[DiscoveryConfig] = None) -> 'ServiceDiscovery':
        """Create or return the singleton instance."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, config: Optional[DiscoveryConfig] = None) -> None:
        """Initialize the ServiceDiscovery singleton.

        Args:
            config: Discovery configuration. Only used on first initialization.
        """
        if not ServiceDiscovery._initialized and config is not None:
            self.logger = get_logger(__name__)
            log_function_entry(self.logger, "__init__",
                             clusters_count=len(config.clusters),
                             scan_interval=config.scan_interval)

            self.config = config
            self.domains: Dict[str, DomainInfo] = {}
            self.last_scan: Optional[datetime] = None
            self._domain_filter = re.compile(config.domain_filter) if config.domain_filter else None

            ServiceDiscovery._initialized = True
            self.logger.info("ServiceDiscovery singleton initialized",
                           clusters_count=len(config.clusters),
                           domain_filter=config.domain_filter,
                           scan_interval=config.scan_interval)

            log_function_exit(self.logger, "__init__", status="success")
        elif not ServiceDiscovery._initialized:
            raise RuntimeError("ServiceDiscovery must be initialized with a config on first use")

    @classmethod
    def get_instance(cls) -> 'ServiceDiscovery':
        """Get the singleton instance.

        Returns:
            The singleton ServiceDiscovery instance.

        Raises:
            RuntimeError: If the singleton has not been initialized.
        """
        if cls._instance is None or not cls._initialized:
            raise RuntimeError("ServiceDiscovery singleton not initialized. Call ServiceDiscovery(config) first.")
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Reset the singleton instance. Primarily for testing."""
        cls._instance = None
        cls._initialized = False

    async def scan_all_clusters(self) -> List[DomainInfo]:
        """Scan all enabled clusters for service domains.

        Returns:
            List of discovered domain information.
        """
        async with self._lock:
            log_function_entry(self.logger, "scan_all_clusters",
                             enabled_clusters=[c.name for c in self.config.clusters if c.enabled])

            all_domains = []

            # Scan each enabled cluster
            for cluster_config in self.config.clusters:
                if not cluster_config.enabled:
                    self.logger.debug("Skipping disabled cluster", cluster=cluster_config.name)
                    continue

                cluster_domains = await self._scan_cluster(cluster_config)
                all_domains.extend(cluster_domains)

            # Update internal storage
            self.domains = {domain.domain: domain for domain in all_domains}
            self.last_scan = datetime.utcnow()

            log_discovery_event(self.logger, "scan_completed",
                              total_domains=len(all_domains),
                              clusters_scanned=len([c for c in self.config.clusters if c.enabled]))

            log_function_exit(self.logger, "scan_all_clusters",
                            domains_found=len(all_domains))

            return all_domains

    async def _scan_cluster(self, cluster_config: ClusterConfig) -> List[DomainInfo]:
        """Scan a single cluster for domains.

        Args:
            cluster_config: Configuration for the cluster to scan.

        Returns:
            List of domains found in the cluster.
        """
        log_function_entry(self.logger, "_scan_cluster", cluster=cluster_config.name)

        client = IngressorClient(cluster_config)
        domains = []

        try:
            await client.connect()

            # Determine namespaces to scan
            namespaces = None
            if self.config.include_namespaces:
                namespaces = self.config.include_namespaces

            # Discover domains from Ingress resources
            if self.config.enable_ingress:
                ingress_domains = await client.discover_ingress_domains(namespaces=namespaces)
                domains.extend(ingress_domains)

            # Discover domains from VirtualService resources
            if self.config.enable_istio:
                vs_domains = await client.discover_virtualservice_domains(namespaces=namespaces)
                domains.extend(vs_domains)

            # Apply filters
            domains = self._apply_filters(domains)

            self.logger.info("Cluster scan completed",
                           cluster=cluster_config.name,
                           domains_found=len(domains),
                           ingress_enabled=self.config.enable_ingress,
                           istio_enabled=self.config.enable_istio)

        except Exception as e:
            self.logger.error("Cluster scan failed",
                            cluster=cluster_config.name,
                            error=str(e))
            domains = []
        finally:
            await client.disconnect()

        log_function_exit(self.logger, "_scan_cluster",
                        cluster=cluster_config.name,
                        domains_found=len(domains))

        return domains

    def _apply_filters(self, domains: List[DomainInfo]) -> List[DomainInfo]:
        """Apply domain and namespace filters.

        Args:
            domains: List of domains to filter.

        Returns:
            Filtered list of domains.
        """
        filtered_domains = []

        for domain in domains:
            # Apply domain filter
            if self._domain_filter and not self._domain_filter.match(domain.domain):
                self.logger.debug("Domain filtered out by regex",
                                domain=domain.domain,
                                filter=self.config.domain_filter)
                continue

            # Apply namespace exclusion filter
            if (self.config.exclude_namespaces and
                domain.namespace in self.config.exclude_namespaces):
                self.logger.debug("Domain filtered out by namespace exclusion",
                                domain=domain.domain,
                                namespace=domain.namespace)
                continue

            filtered_domains.append(domain)

        return filtered_domains

    def get_domains(self,
                   environment: Optional[str] = None,
                   cluster: Optional[str] = None,
                   namespace: Optional[str] = None) -> List[DomainInfo]:
        """Get filtered list of discovered domains.

        Args:
            environment: Filter by environment name.
            cluster: Filter by cluster name.
            namespace: Filter by namespace name.

        Returns:
            Filtered and sorted list of domains.
        """
        domains = list(self.domains.values())

        # Apply filters
        if environment:
            domains = [d for d in domains if d.environment == environment]
        if cluster:
            domains = [d for d in domains if d.cluster == cluster]
        if namespace:
            domains = [d for d in domains if d.namespace == namespace]

        # Sort by domain name for consistent ordering
        return sorted(domains, key=lambda d: d.domain)

    def get_summary(self) -> ServiceSummary:
        """Get summary statistics of discovered services.

        Returns:
            Summary statistics including counts by environment, cluster, namespace.
        """
        domains = list(self.domains.values())

        # Count by environment
        by_environment = {}
        for domain in domains:
            by_environment[domain.environment] = by_environment.get(domain.environment, 0) + 1

        # Count by cluster
        by_cluster = {}
        for domain in domains:
            by_cluster[domain.cluster] = by_cluster.get(domain.cluster, 0) + 1

        # Count by namespace
        by_namespace = {}
        for domain in domains:
            by_namespace[domain.namespace] = by_namespace.get(domain.namespace, 0) + 1

        return ServiceSummary(
            total_domains=len(domains),
            by_environment=by_environment,
            by_cluster=by_cluster,
            by_namespace=by_namespace,
            last_scan=self.last_scan
        )
