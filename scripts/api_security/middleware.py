from fastapi import Request, Response
from fastapi.responses import JSONResponse
import re

# Basic OWASP Top 10 API risk checks (demo only)
def api_security_middleware(request: Request, call_next):
    # Block requests with suspicious User-Agent
    user_agent = request.headers.get("user-agent", "")
    if "sqlmap" in user_agent.lower():
        return JSONResponse(status_code=403, content={"detail": "Blocked: Suspicious User-Agent"})
    # Block requests with SQL injection patterns in query
    for value in request.query_params.values():
        if re.search(r"('|--|;|\bOR\b|\bAND\b)", value, re.IGNORECASE):
            return JSONResponse(status_code=400, content={"detail": "Blocked: SQLi pattern detected"})
    # Block requests with missing Content-Type for POST/PUT
    if request.method in ("POST", "PUT") and request.headers.get("content-type") is None:
        return JSONResponse(status_code=415, content={"detail": "Missing Content-Type header"})
    return call_next(request)

# Scan responses for sensitive data (demo)
def sensitive_data_middleware(request: Request, call_next):
    response = await call_next(request)
    if response.media_type == "application/json":
        body = b""
        async for chunk in response.body_iterator:
            body += chunk
        text = body.decode()
        # Scan for sensitive keywords
        if any(keyword in text for keyword in ["SECRET", "TOKEN", "PASSWORD"]):
            return JSONResponse(status_code=500, content={"detail": "Sensitive data leak detected!"})
        # Rebuild response
        return Response(content=body, status_code=response.status_code, headers=dict(response.headers), media_type="application/json")
    return response
