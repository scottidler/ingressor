"""Core service discovery functionality."""

import asyncio
import re
from datetime import datetime
from typing import Dict, List, Optional

from kubernetes import client, config
from kubernetes.client.rest import ApiException

from .logging_config import get_logger, log_function_entry, log_function_exit, log_k8s_operation, log_discovery_event
from .models import ClusterConfig, DomainInfo, DiscoveryConfig, ServiceSummary

logger = get_logger(__name__)


class IngressorClient:
    """Client for interacting with Kubernetes clusters to discover domains."""
    
    def __init__(self, cluster_config: ClusterConfig):
        log_function_entry(logger, "IngressorClient.__init__", cluster_name=cluster_config.name, environment=cluster_config.environment)
        self.cluster_config = cluster_config
        self._k8s_client: Optional[client.ApiClient] = None
        self._networking_v1: Optional[client.NetworkingV1Api] = None
        self._custom_objects: Optional[client.CustomObjectsApi] = None
        logger.debug("IngressorClient initialized", cluster_name=cluster_config.name, environment=cluster_config.environment)
    
    async def connect(self) -> None:
        """Initialize connection to the Kubernetes cluster."""
        log_function_entry(logger, "connect", cluster_name=self.cluster_config.name)
        log_k8s_operation(logger, "connect", self.cluster_config.name, 
                         kubeconfig_path=self.cluster_config.kubeconfig_path,
                         context=self.cluster_config.context)
        
        try:
            if self.cluster_config.kubeconfig_path:
                logger.debug("Loading kubeconfig from file", 
                           kubeconfig_path=self.cluster_config.kubeconfig_path,
                           context=self.cluster_config.context,
                           cluster=self.cluster_config.name)
                config.load_kube_config(
                    config_file=self.cluster_config.kubeconfig_path,
                    context=self.cluster_config.context
                )
            else:
                logger.debug("Loading in-cluster config", cluster=self.cluster_config.name)
                config.load_incluster_config()
            
            logger.debug("Initializing Kubernetes API clients", cluster=self.cluster_config.name)
            self._k8s_client = client.ApiClient()
            self._networking_v1 = client.NetworkingV1Api(self._k8s_client)
            self._custom_objects = client.CustomObjectsApi(self._k8s_client)
            
            logger.info("Successfully connected to cluster", cluster=self.cluster_config.name)
            log_function_exit(logger, "connect", cluster_name=self.cluster_config.name, status="success")
            
        except Exception as e:
            logger.error("Failed to connect to cluster", 
                        cluster=self.cluster_config.name, 
                        error=str(e),
                        kubeconfig_path=self.cluster_config.kubeconfig_path,
                        context=self.cluster_config.context)
            log_function_exit(logger, "connect", cluster_name=self.cluster_config.name, status="error", error=str(e))
            raise
    
    async def discover_ingress_domains(self, namespaces: Optional[List[str]] = None) -> List[DomainInfo]:
        """Discover domains from Ingress resources."""
        log_function_entry(logger, "discover_ingress_domains", 
                          cluster=self.cluster_config.name, 
                          namespaces=namespaces)
        log_k8s_operation(logger, "discover_ingress", self.cluster_config.name, namespaces=namespaces)
        
        if not self._networking_v1:
            logger.debug("API client not initialized, connecting", cluster=self.cluster_config.name)
            await self.connect()
        
        domains = []
        
        try:
            if namespaces:
                logger.debug("Discovering ingresses in specific namespaces", 
                           cluster=self.cluster_config.name, 
                           namespaces=namespaces)
                ingresses = []
                for ns in namespaces:
                    try:
                        logger.debug("Listing ingresses in namespace", 
                                   cluster=self.cluster_config.name, 
                                   namespace=ns)
                        ns_ingresses = self._networking_v1.list_namespaced_ingress(namespace=ns)
                        ingresses.extend(ns_ingresses.items)
                        logger.debug("Found ingresses in namespace", 
                                   cluster=self.cluster_config.name,
                                   namespace=ns, 
                                   count=len(ns_ingresses.items))
                    except ApiException as e:
                        logger.warning("Could not list ingresses in namespace", 
                                     cluster=self.cluster_config.name,
                                     namespace=ns, 
                                     error=str(e))
            else:
                logger.debug("Discovering ingresses in all namespaces", cluster=self.cluster_config.name)
                ingresses_response = self._networking_v1.list_ingress_for_all_namespaces()
                ingresses = ingresses_response.items
                logger.debug("Found total ingresses", 
                           cluster=self.cluster_config.name, 
                           count=len(ingresses))
            
            for ingress in ingresses:
                if not ingress.spec or not ingress.spec.rules:
                    logger.debug("Skipping ingress without spec or rules", 
                               cluster=self.cluster_config.name,
                               ingress_name=ingress.metadata.name,
                               namespace=ingress.metadata.namespace)
                    continue
                
                logger.debug("Processing ingress", 
                           cluster=self.cluster_config.name,
                           ingress_name=ingress.metadata.name,
                           namespace=ingress.metadata.namespace,
                           rules_count=len(ingress.spec.rules))
                
                for rule in ingress.spec.rules:
                    if not rule.host:
                        logger.debug("Skipping rule without host", 
                                   cluster=self.cluster_config.name,
                                   ingress_name=ingress.metadata.name)
                        continue
                    
                    # Check for TLS configuration
                    tls_enabled = bool(
                        ingress.spec.tls and 
                        any(rule.host in tls.hosts for tls in ingress.spec.tls if tls.hosts)
                    )
                    
                    logger.debug("Found domain in ingress", 
                               cluster=self.cluster_config.name,
                               domain=rule.host,
                               namespace=ingress.metadata.namespace,
                               ingress_name=ingress.metadata.name,
                               tls_enabled=tls_enabled)
                    
                    domain_info = DomainInfo(
                        domain=rule.host,
                        cluster=self.cluster_config.name,
                        environment=self.cluster_config.environment,
                        namespace=ingress.metadata.namespace,
                        ingress_name=ingress.metadata.name,
                        resource_type="ingress",
                        labels=ingress.metadata.labels or {},
                        annotations=ingress.metadata.annotations or {},
                        tls_enabled=tls_enabled,
                    )
                    domains.append(domain_info)
            
            log_discovery_event(logger, "ingress_discovery_completed", 
                              cluster=self.cluster_config.name,
                              domains_found=len(domains))
            logger.info("Discovered domains from Ingress resources", 
                       cluster=self.cluster_config.name,
                       domains_count=len(domains))
            
        except Exception as e:
            logger.error("Error discovering ingress domains", 
                        cluster=self.cluster_config.name, 
                        error=str(e))
        
        log_function_exit(logger, "discover_ingress_domains", 
                         cluster=self.cluster_config.name, 
                         domains_count=len(domains))
        return domains
    
    async def discover_virtualservice_domains(self, namespaces: Optional[List[str]] = None) -> List[DomainInfo]:
        """Discover domains from Istio VirtualService resources."""
        if not self._custom_objects:
            await self.connect()
        
        domains = []
        
        try:
            if namespaces:
                virtualservices = []
                for ns in namespaces:
                    try:
                        vs_response = self._custom_objects.list_namespaced_custom_object(
                            group="networking.istio.io",
                            version="v1beta1",
                            namespace=ns,
                            plural="virtualservices"
                        )
                        virtualservices.extend(vs_response.get("items", []))
                    except ApiException as e:
                        logger.warning(f"Could not list VirtualServices in namespace {ns}: {e}")
            else:
                vs_response = self._custom_objects.list_cluster_custom_object(
                    group="networking.istio.io",
                    version="v1beta1",
                    plural="virtualservices"
                )
                virtualservices = vs_response.get("items", [])
            
            for vs in virtualservices:
                spec = vs.get("spec", {})
                hosts = spec.get("hosts", [])
                
                for host in hosts:
                    # Skip internal service names (without dots)
                    if "." not in host or host.endswith(".local"):
                        continue
                    
                    metadata = vs.get("metadata", {})
                    domain_info = DomainInfo(
                        domain=host,
                        cluster=self.cluster_config.name,
                        environment=self.cluster_config.environment,
                        namespace=metadata.get("namespace", "default"),
                        service_name=metadata.get("name"),
                        resource_type="virtualservice",
                        labels=metadata.get("labels", {}),
                        annotations=metadata.get("annotations", {}),
                        tls_enabled=bool(spec.get("tls")),
                    )
                    domains.append(domain_info)
            
            logger.info(f"Discovered {len(domains)} domains from VirtualService resources in {self.cluster_config.name}")
            
        except Exception as e:
            logger.error(f"Error discovering VirtualService domains in {self.cluster_config.name}: {e}")
        
        return domains
    
    async def disconnect(self) -> None:
        """Clean up the connection."""
        if self._k8s_client:
            await self._k8s_client.close()


class ServiceDiscovery:
    """Main service discovery orchestrator."""
    
    def __init__(self, config: DiscoveryConfig):
        self.config = config
        self.domains: Dict[str, DomainInfo] = {}
        self.last_scan: Optional[datetime] = None
    
    async def scan_all_clusters(self) -> List[DomainInfo]:
        """Scan all configured clusters for domains."""
        all_domains = []
        
        tasks = []
        for cluster_config in self.config.clusters:
            if not cluster_config.enabled:
                continue
            
            task = self._scan_cluster(cluster_config)
            tasks.append(task)
        
        # Run cluster scans in parallel
        cluster_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in cluster_results:
            if isinstance(result, Exception):
                logger.error(f"Cluster scan failed: {result}")
            else:
                all_domains.extend(result)
        
        # Update internal storage
        self.domains = {domain.domain: domain for domain in all_domains}
        self.last_scan = datetime.utcnow()
        
        logger.info(f"Completed scan of all clusters. Found {len(all_domains)} total domains.")
        return all_domains
    
    async def _scan_cluster(self, cluster_config: ClusterConfig) -> List[DomainInfo]:
        """Scan a single cluster for domains."""
        client = IngressorClient(cluster_config)
        domains = []
        
        try:
            await client.connect()
            
            # Determine namespaces to scan
            namespaces = None
            if self.config.include_namespaces:
                namespaces = self.config.include_namespaces
            
            # Discover from Ingress resources
            if self.config.enable_ingress:
                ingress_domains = await client.discover_ingress_domains(namespaces)
                domains.extend(ingress_domains)
            
            # Discover from VirtualService resources
            if self.config.enable_istio:
                vs_domains = await client.discover_virtualservice_domains(namespaces)
                domains.extend(vs_domains)
            
            # Apply domain filtering
            if self.config.domain_filter:
                pattern = re.compile(self.config.domain_filter)
                domains = [d for d in domains if pattern.search(d.domain)]
            
            # Filter out excluded namespaces
            if self.config.exclude_namespaces:
                domains = [d for d in domains if d.namespace not in self.config.exclude_namespaces]
            
        except Exception as e:
            logger.error(f"Error scanning cluster {cluster_config.name}: {e}")
        finally:
            await client.disconnect()
        
        return domains
    
    def get_domains(
        self, 
        environment: Optional[str] = None,
        cluster: Optional[str] = None,
        namespace: Optional[str] = None
    ) -> List[DomainInfo]:
        """Get filtered list of discovered domains."""
        domains = list(self.domains.values())
        
        if environment:
            domains = [d for d in domains if d.environment == environment]
        
        if cluster:
            domains = [d for d in domains if d.cluster == cluster]
        
        if namespace:
            domains = [d for d in domains if d.namespace == namespace]
        
        return sorted(domains, key=lambda x: x.domain)
    
    def get_summary(self) -> ServiceSummary:
        """Get summary statistics of discovered services."""
        domains = list(self.domains.values())
        
        by_environment = {}
        by_cluster = {}
        by_namespace = {}
        
        for domain in domains:
            by_environment[domain.environment] = by_environment.get(domain.environment, 0) + 1
            by_cluster[domain.cluster] = by_cluster.get(domain.cluster, 0) + 1
            by_namespace[domain.namespace] = by_namespace.get(domain.namespace, 0) + 1
        
        return ServiceSummary(
            total_domains=len(domains),
            by_environment=by_environment,
            by_cluster=by_cluster,
            by_namespace=by_namespace,
            last_scan=self.last_scan
        ) 