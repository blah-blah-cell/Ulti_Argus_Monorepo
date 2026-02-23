"""
API wrapper for Aegis Daemon.
"""
import os
import logging
from typing import Dict, Any, Optional

from fastapi import FastAPI, HTTPException
from prometheus_client import start_http_server, Gauge, Info

from .daemon import AegisDaemon

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Aegis Brain API", version="0.1.0")

# Global daemon instance
daemon: Optional[AegisDaemon] = None

# Prometheus Metrics
DAEMON_INFO = Info("aegis_daemon_info", "Aegis Daemon Information")
HEALTH_STATUS = Gauge("aegis_health_status", "Overall health status (1=Healthy, 0=Unhealthy)")
COMPONENTS_HEALTHY = Gauge("aegis_components_healthy", "Number of healthy components")
TOTAL_COMPONENTS = Gauge("aegis_total_components", "Total number of components")

@app.on_event("startup")
async def startup_event():
    global daemon

    # Start Prometheus metrics server on port 9090
    try:
        start_http_server(9090)
        logger.info("Prometheus metrics server started on port 9090")
    except Exception as e:
        logger.error(f"Failed to start Prometheus metrics server: {e}")

    # Initialize Daemon
    config_path = os.environ.get("ARGUS_CONFIG_FILE")
    if not config_path:
        config_path = "/etc/argus/aegis.yaml"

    logger.info(f"Initializing Aegis Daemon with config: {config_path}")

    try:
        if os.path.exists(config_path):
            daemon = AegisDaemon(config_path)
            if daemon.start():
                logger.info("Aegis Daemon started successfully")
            else:
                logger.error("Aegis Daemon failed to start")
        else:
            logger.warning(f"Config file not found at {config_path}. Daemon not started.")
    except Exception as e:
        logger.error(f"Failed to initialize Aegis Daemon: {e}")

@app.on_event("shutdown")
async def shutdown_event():
    global daemon
    if daemon:
        logger.info("Stopping Aegis Daemon...")
        daemon.stop()
        logger.info("Aegis Daemon stopped")

@app.get("/api/status")
async def get_status() -> Dict[str, Any]:
    if not daemon:
         raise HTTPException(status_code=503, detail="Daemon not initialized")

    status = daemon.get_status()

    # Update Prometheus metrics
    health = status.get("health", {})
    overall = health.get("overall_health", "unknown")
    HEALTH_STATUS.set(1 if overall == "healthy" else 0)
    COMPONENTS_HEALTHY.set(health.get("components_healthy", 0))
    TOTAL_COMPONENTS.set(health.get("total_components", 0))

    service_info = health.get("service_info", {})
    DAEMON_INFO.info({
        "version": "0.1.0",
        "start_time": str(service_info.get("start_time", "")),
        "status": overall
    })

    return status

@app.get("/health")
async def health_check():
    """Simple health check for Docker/Kubernetes."""
    if not daemon:
        return {"status": "starting_or_failed"}
    return {"status": "ok"}
