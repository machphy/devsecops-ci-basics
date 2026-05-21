# discovery.py
from fastapi import FastAPI
from typing import List, Dict

def register_discovery_events(app: FastAPI, discovered_endpoints: List[Dict]):
    """Attach event handlers to discover endpoints on startup."""
    @app.on_event("startup")
    async def discover():
        discovered_endpoints.clear()
        for route in app.routes:
            if hasattr(route, 'path') and hasattr(route, 'methods'):
                discovered_endpoints.append({
                    "path": route.path,
                    "methods": list(route.methods)
                })

def get_discovered_endpoints(discovered_endpoints: List[Dict]):
    return discovered_endpoints
