from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from middleware import (
    api_security_middleware,
    sensitive_data_middleware
)
from discovery import register_discovery_events, get_discovered_endpoints
from schemas import UserRequest, UserResponse

app = FastAPI()

# Register endpoint discovery events
discovered_endpoints = []
register_discovery_events(app, discovered_endpoints)

# Add security middlewares
app.middleware('http')(api_security_middleware)
app.middleware('http')(sensitive_data_middleware)

@app.get("/endpoints")
def endpoints():
    """List discovered API endpoints."""
    return {"endpoints": get_discovered_endpoints(discovered_endpoints)}

@app.post("/user", response_model=UserResponse)
def create_user(user: UserRequest):
    """Create a user (demo endpoint)."""
    # Simulate sensitive data in response
    return UserResponse(
        username=user.username,
        email=user.email,
        token="SECRET_TOKEN_123"
    )

@app.get("/health")
def health():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
