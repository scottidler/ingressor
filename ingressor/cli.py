"""Command-line interface for ingressor."""

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

from .logging_config import setup_logging, get_logger

logger = get_logger(__name__)


def serve_command(args: argparse.Namespace) -> None:
    """Start the ingressor API server."""
    # Import heavy dependencies only when needed
    import uvicorn
    import yaml
    from .api import app, initialize_discovery
    from .models import DiscoveryConfig
    from .logging_config import log_function_entry, log_function_exit
    
    setup_logging(args.verbose)
    log_function_entry(logger, "serve_command", host=args.host, port=args.port, config=args.config, verbose=args.verbose)
    
    # Load configuration
    config_path = None
    if args.config:
        config_path = Path(args.config)
        if not config_path.exists():
            print(f"Configuration file not found: {config_path}", file=sys.stderr)
            sys.exit(1)
    else:
        # Look for config in common locations
        for path in [Path("ingressor.yaml"), Path("config.yaml"), Path("/etc/ingressor/config.yaml")]:
            if path.exists():
                config_path = path
                break
    
    if config_path:
        try:
            logger.debug("Loading configuration file", config_path=str(config_path))
            with open(config_path) as f:
                config_data = yaml.safe_load(f)
            discovery_config = DiscoveryConfig(**config_data)
            logger.info("Configuration loaded successfully", 
                       config_path=str(config_path), 
                       clusters_count=len(discovery_config.clusters),
                       scan_interval=discovery_config.scan_interval)
            print(f"Loaded configuration from {config_path}")
        except Exception as e:
            logger.error("Failed to load configuration", config_path=str(config_path), error=str(e))
            print(f"Error loading configuration: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        logger.warning("No configuration file found, using defaults")
        print("No configuration file found. Using default configuration.")
        discovery_config = DiscoveryConfig()
    
    # Initialize the discovery service
    logger.debug("Initializing discovery service")
    initialize_discovery(discovery_config)
    
    # Start the server
    logger.info("Starting ingressor server", host=args.host, port=args.port, reload=args.reload)
    print(f"Starting ingressor server on {args.host}:{args.port}")
    
    log_function_exit(logger, "serve_command", status="starting_server")
    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info" if not args.verbose else "debug"
    )


def scan_command(args: argparse.Namespace) -> None:
    """Scan clusters and display discovered domains."""
    # Import heavy dependencies only when needed  
    import yaml
    from .core import ServiceDiscovery
    from .models import DiscoveryConfig
    
    setup_logging(args.verbose)
    
    # Load configuration
    if not args.config:
        print("No configuration file specified. Please provide a config file.", file=sys.stderr)
        sys.exit(1)
    
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"Configuration file not found: {config_path}", file=sys.stderr)
        sys.exit(1)
    
    try:
        with open(config_path) as f:
            config_data = yaml.safe_load(f)
        discovery_config = DiscoveryConfig(**config_data)
    except Exception as e:
        print(f"Error loading configuration: {e}", file=sys.stderr)
        sys.exit(1)
    
    async def run_scan():
        discovery = ServiceDiscovery(discovery_config)
        
        print("Starting cluster scan...")
        domains = await discovery.scan_all_clusters()
        
        # Apply filters
        filtered_domains = discovery.get_domains(
            environment=args.environment,
            cluster=args.cluster,
            namespace=args.namespace
        )
        
        if args.output == "json":
            data = [domain.model_dump() for domain in filtered_domains]
            print(json.dumps(data, indent=2, default=str))
        elif args.output == "yaml":
            data = [domain.model_dump() for domain in filtered_domains]
            print(yaml.dump(data, default_flow_style=False))
        else:
            # Table format
            if not filtered_domains:
                print("No domains found.")
                return
            
            print(f"\nFound {len(filtered_domains)} domains:\n")
            print(f"{'Domain':<50} {'Environment':<12} {'Cluster':<15} {'Namespace':<20} {'TLS':<5}")
            print("-" * 102)
            
            for domain in filtered_domains:
                tls_status = "✓" if domain.tls_enabled else "✗"
                print(f"{domain.domain:<50} {domain.environment:<12} {domain.cluster:<15} {domain.namespace:<20} {tls_status:<5}")
    
    asyncio.run(run_scan())


def init_config_command(args: argparse.Namespace) -> None:
    """Generate a sample configuration file."""
    import yaml
    
    sample_config = {
        "clusters": [
            {
                "name": "prod-us-west-1",
                "kubeconfig_path": "~/.kube/config",
                "context": "prod-us-west-1",
                "environment": "prod",
                "region": "us-west-1",
                "enabled": True
            },
            {
                "name": "staging-us-west-1", 
                "kubeconfig_path": "~/.kube/config",
                "context": "staging-us-west-1",
                "environment": "staging",
                "region": "us-west-1",
                "enabled": True
            }
        ],
        "scan_interval": 300,
        "domain_filter": r".*\.tatari\.dev$",
        "include_namespaces": [],
        "exclude_namespaces": ["kube-system", "kube-public", "istio-system"],
        "enable_istio": True,
        "enable_ingress": True
    }
    
    config_yaml = yaml.dump(sample_config, default_flow_style=False, sort_keys=False)
    
    if args.output:
        output_path = Path(args.output)
        output_path.write_text(config_yaml)
        print(f"Sample configuration written to {output_path}")
    else:
        print("Sample configuration:\n")
        print(config_yaml)


def validate_config_command(args: argparse.Namespace) -> None:
    """Validate a configuration file."""
    # Import only when needed
    from .models import DiscoveryConfig
    
    config_path = Path(args.config)
    
    try:
        with open(config_path) as f:
            config_data = yaml.safe_load(f)
        
        discovery_config = DiscoveryConfig(**config_data)
        print(f"✓ Configuration file {config_path} is valid")
        
        # Show summary
        print(f"\nConfiguration summary:")
        print(f"  Clusters: {len(discovery_config.clusters)}")
        print(f"  Scan interval: {discovery_config.scan_interval}s")
        print(f"  Domain filter: {discovery_config.domain_filter or 'None'}")
        print(f"  Istio enabled: {discovery_config.enable_istio}")
        print(f"  Ingress enabled: {discovery_config.enable_ingress}")
        
        # List clusters
        if discovery_config.clusters:
            print(f"\nConfigured clusters:")
            for cluster in discovery_config.clusters:
                status = "enabled" if cluster.enabled else "disabled"
                print(f"  - {cluster.name} ({cluster.environment}) - {status}")
        
    except Exception as e:
        print(f"✗ Configuration file {config_path} is invalid: {e}", file=sys.stderr)
        sys.exit(1)


def version_command(args: argparse.Namespace) -> None:
    """Show version information."""
    from . import __version__, __author__
    print(f"Ingressor {__version__}")
    print(f"Author: {__author__}")


def main() -> None:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Ingressor: Multi-cluster Kubernetes service discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Global options
    parser.add_argument(
        "--verbose", "-v", 
        action="store_true", 
        help="Enable verbose logging"
    )
    
    # Subcommands
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Serve command
    serve_parser = subparsers.add_parser("serve", help="Start the ingressor API server")
    serve_parser.add_argument(
        "--config", "-c", 
        help="Configuration file path"
    )
    serve_parser.add_argument(
        "--host", 
        default="0.0.0.0", 
        help="Host to bind to (default: 0.0.0.0)"
    )
    serve_parser.add_argument(
        "--port", 
        type=int, 
        default=8000, 
        help="Port to bind to (default: 8000)"
    )
    serve_parser.add_argument(
        "--reload", 
        action="store_true", 
        help="Enable auto-reload for development"
    )
    serve_parser.set_defaults(func=serve_command)
    
    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan clusters and display discovered domains")
    scan_parser.add_argument(
        "--config", "-c", 
        required=True,
        help="Configuration file path"
    )
    scan_parser.add_argument(
        "--output", "-o", 
        choices=["json", "yaml", "table"], 
        default="table",
        help="Output format (default: table)"
    )
    scan_parser.add_argument(
        "--environment", "-e", 
        help="Filter by environment"
    )
    scan_parser.add_argument(
        "--cluster", 
        help="Filter by cluster"
    )
    scan_parser.add_argument(
        "--namespace", "-n", 
        help="Filter by namespace"
    )
    scan_parser.set_defaults(func=scan_command)
    
    # Init-config command
    init_parser = subparsers.add_parser("init-config", help="Generate a sample configuration file")
    init_parser.add_argument(
        "--output", "-o", 
        help="Output file path (default: stdout)"
    )
    init_parser.set_defaults(func=init_config_command)
    
    # Validate-config command
    validate_parser = subparsers.add_parser("validate-config", help="Validate a configuration file")
    validate_parser.add_argument(
        "--config", "-c", 
        required=True,
        help="Configuration file path"
    )
    validate_parser.set_defaults(func=validate_config_command)
    
    # Version command
    version_parser = subparsers.add_parser("version", help="Show version information")
    version_parser.set_defaults(func=version_command)
    
    # Parse arguments and execute command
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    args.func(args)


if __name__ == "__main__":
    main() 