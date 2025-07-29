"""FastAPI REST API for ingressor service discovery."""

import asyncio
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware

from .discovery import ServiceDiscovery
from .logging_config import get_logger, log_api_request, log_api_response, log_function_entry, log_function_exit
from .models import DomainInfo, DiscoveryConfig, ServiceSummary

logger = get_logger(__name__)

app = FastAPI(
    title="Ingressor",
    description="Multi-cluster Kubernetes service discovery for external domains",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all HTTP requests and responses."""
    start_time = asyncio.get_event_loop().time()

    # Log request
    log_api_request(logger, request.method, str(request.url.path),
                   client_ip=request.client.host if request.client else "unknown",
                   user_agent=request.headers.get("user-agent", "unknown"))

    # Process request
    response = await call_next(request)

    # Calculate duration
    duration = asyncio.get_event_loop().time() - start_time

    # Log response
    log_api_response(logger, request.method, str(request.url.path),
                    response.status_code,
                    duration_ms=round(duration * 1000, 2))

    return response

async def get_discovery() -> ServiceDiscovery:
    """Get the singleton ServiceDiscovery instance."""
    try:
        return ServiceDiscovery.get_instance()
    except RuntimeError:
        raise HTTPException(status_code=503, detail="Service discovery not initialized")


def initialize_discovery(config: DiscoveryConfig) -> None:
    """Initialize the singleton ServiceDiscovery instance."""
    log_function_entry(logger, "initialize_discovery",
                      clusters_count=len(config.clusters),
                      scan_interval=config.scan_interval)

    # Create the singleton instance
    ServiceDiscovery(config)

    logger.info("Service discovery initialized via singleton",
               clusters_count=len(config.clusters),
               scan_interval=config.scan_interval,
               domain_filter=config.domain_filter,
               enable_istio=config.enable_istio,
               enable_ingress=config.enable_ingress)
    log_function_exit(logger, "initialize_discovery", status="success")



@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "ingressor"}


@app.get("/domains", response_model=List[DomainInfo])
async def get_domains(
    environment: Optional[str] = Query(None, description="Filter by environment"),
    cluster: Optional[str] = Query(None, description="Filter by cluster"),
    namespace: Optional[str] = Query(None, description="Filter by namespace"),
):
    """Get all discovered domains with optional filtering."""
    logger.debug("Getting domains",
                environment=environment,
                cluster=cluster,
                namespace=namespace)

    disc = await get_discovery()
    domains = disc.get_domains(
        environment=environment,
        cluster=cluster,
        namespace=namespace
    )

    logger.debug("Returning filtered domains",
                count=len(domains),
                environment=environment,
                cluster=cluster,
                namespace=namespace)
    return domains


@app.get("/domains/{domain_name}", response_model=DomainInfo)
async def get_domain(domain_name: str):
    """Get information about a specific domain."""
    disc = await get_discovery()

    if domain_name not in disc.domains:
        raise HTTPException(status_code=404, detail=f"Domain {domain_name} not found")

    return disc.domains[domain_name]


@app.get("/summary", response_model=ServiceSummary)
async def get_summary():
    """Get summary statistics of discovered services."""
    disc = await get_discovery()
    return disc.get_summary()


@app.get("/environments")
async def get_environments():
    """Get list of all environments."""
    disc = await get_discovery()
    summary = disc.get_summary()
    return {"environments": list(summary.by_environment.keys())}


@app.get("/clusters")
async def get_clusters():
    """Get list of all clusters."""
    disc = await get_discovery()
    summary = disc.get_summary()
    return {"clusters": list(summary.by_cluster.keys())}


@app.get("/namespaces")
async def get_namespaces():
    """Get list of all namespaces."""
    disc = await get_discovery()
    summary = disc.get_summary()
    return {"namespaces": list(summary.by_namespace.keys())}


@app.post("/scan")
async def trigger_scan():
    """Manually trigger a scan of all clusters."""
    logger.info("Manual scan triggered")
    disc = await get_discovery()

    try:
        logger.debug("Starting manual cluster scan")
        domains = await disc.scan_all_clusters()

        result = {
            "status": "success",
            "message": f"Scan completed. Discovered {len(domains)} domains.",
            "domains_count": len(domains)
        }

        logger.info("Manual scan completed successfully",
                   domains_count=len(domains))
        return result

    except Exception as e:
        logger.error("Manual scan failed", error=str(e))
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@app.get("/config")
async def get_config():
    """Get current discovery configuration (sanitized)."""
    disc = await get_discovery()

    # Return sanitized config (without sensitive data)
    config_dict = disc.config.model_dump()

    # Remove sensitive kubeconfig paths
    for cluster in config_dict.get("clusters", []):
        if "kubeconfig_path" in cluster:
            cluster["kubeconfig_path"] = "***" if cluster["kubeconfig_path"] else None

    return config_dict


# Background task for periodic scanning
async def periodic_scan():
    """Background task to periodically scan clusters."""
    logger.info("Starting periodic scan background task")

    while True:
        try:
            discovery = await get_discovery()
            logger.debug("Starting periodic cluster scan")
            domains = await discovery.scan_all_clusters()
            logger.info("Periodic scan completed successfully",
                       domains_count=len(domains))

            scan_interval = discovery.config.scan_interval
            logger.debug("Sleeping until next scan", interval_seconds=scan_interval)
            await asyncio.sleep(scan_interval)

        except Exception as e:
            logger.error("Periodic scan failed", error=str(e))
            logger.info("Retrying periodic scan in 60 seconds")
            await asyncio.sleep(60)  # Wait a minute before retrying


@app.on_event("startup")
async def startup_event():
    """Start background tasks on application startup."""
    try:
        discovery = await get_discovery()
        # Perform initial scan
        try:
            await discovery.scan_all_clusters()
            logger.info("Initial scan completed")
        except Exception as e:
            logger.error(f"Initial scan failed: {e}")

        # Start periodic scanning in background
        asyncio.create_task(periodic_scan())
    except Exception as e:
        logger.warning(f"Discovery not initialized yet: {e}")


@app.on_event("shutdown")
async def shutdown_event():
    """Clean up on application shutdown."""
    logger.info("Shutting down ingressor API")
