"""Ingressor: Multi-cluster Kubernetes service discovery for external domains."""

__version__ = "0.1.0"
__author__ = "Scott Idler"
__email__ = "scott@idler.me"

# Lazy imports to avoid loading heavy dependencies for CLI usage
__all__ = [
    "IngressorClient",
    "ServiceDiscovery",
    "DomainInfo",
    "ClusterConfig",
]

def __getattr__(name):
    if name == "IngressorClient":
        from .ingressor import IngressorClient
        return IngressorClient
    elif name == "ServiceDiscovery":
        from .discovery import ServiceDiscovery
        return ServiceDiscovery
    elif name == "DomainInfo":
        from .models import DomainInfo
        return DomainInfo
    elif name == "ClusterConfig":
        from .models import ClusterConfig
        return ClusterConfig
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
