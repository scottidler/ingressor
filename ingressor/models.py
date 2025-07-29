"""Data models for ingressor service discovery."""

from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel, Field, HttpUrl


class ClusterConfig(BaseModel):
    """Configuration for a Kubernetes cluster."""
    
    name: str = Field(..., description="Cluster name identifier")
    kubeconfig_path: Optional[str] = Field(None, description="Path to kubeconfig file")
    context: Optional[str] = Field(None, description="Kubernetes context name")
    environment: str = Field(..., description="Environment (prod, staging, test, etc.)")
    region: Optional[str] = Field(None, description="Cloud region")
    enabled: bool = Field(True, description="Whether to scan this cluster")


class DomainInfo(BaseModel):
    """Information about a discovered domain."""
    
    domain: str = Field(..., description="The external domain name")
    cluster: str = Field(..., description="Source cluster name")
    environment: str = Field(..., description="Environment (prod, staging, test, etc.)")
    namespace: str = Field(..., description="Kubernetes namespace")
    service_name: Optional[str] = Field(None, description="Associated service name")
    ingress_name: Optional[str] = Field(None, description="Ingress resource name")
    resource_type: str = Field(..., description="Resource type (ingress, virtualservice)")
    labels: Dict[str, str] = Field(default_factory=dict, description="Resource labels")
    annotations: Dict[str, str] = Field(default_factory=dict, description="Resource annotations")
    tls_enabled: bool = Field(False, description="Whether TLS is configured")
    discovered_at: datetime = Field(default_factory=datetime.utcnow, description="Discovery timestamp")
    last_seen: datetime = Field(default_factory=datetime.utcnow, description="Last seen timestamp")


class ServiceSummary(BaseModel):
    """Summary statistics for discovered services."""
    
    total_domains: int = Field(0, description="Total number of domains")
    by_environment: Dict[str, int] = Field(default_factory=dict, description="Count by environment")
    by_cluster: Dict[str, int] = Field(default_factory=dict, description="Count by cluster")
    by_namespace: Dict[str, int] = Field(default_factory=dict, description="Count by namespace")
    last_scan: Optional[datetime] = Field(None, description="Last scan timestamp")


class DiscoveryConfig(BaseModel):
    """Configuration for the discovery process."""
    
    clusters: List[ClusterConfig] = Field(default_factory=list, description="Cluster configurations")
    scan_interval: int = Field(300, description="Scan interval in seconds")
    domain_filter: Optional[str] = Field(None, description="Domain filter pattern (regex)")
    include_namespaces: List[str] = Field(default_factory=list, description="Namespaces to include")
    exclude_namespaces: List[str] = Field(default_factory=lambda: ["kube-system", "kube-public"], description="Namespaces to exclude")
    enable_istio: bool = Field(True, description="Enable Istio VirtualService discovery")
    enable_ingress: bool = Field(True, description="Enable Ingress discovery") 