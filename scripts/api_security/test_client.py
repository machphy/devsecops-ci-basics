# test_client.py
import httpx

BASE_URL = "http://localhost:8000"

def test_health():
    r = httpx.get(f"{BASE_URL}/health")
    print("/health:", r.status_code, r.json())

def test_endpoints():
    r = httpx.get(f"{BASE_URL}/endpoints")
    print("/endpoints:", r.status_code, r.json())

def test_create_user():
    data = {"username": "alice", "email": "alice@example.com"}
    r = httpx.post(f"{BASE_URL}/user", json=data)
    print("/user:", r.status_code, r.json())

def test_blocked_user_agent():
    headers = {"User-Agent": "sqlmap"}
    r = httpx.get(f"{BASE_URL}/health", headers=headers)
    print("Blocked UA:", r.status_code, r.json())

def test_sql_injection():
    r = httpx.get(f"{BASE_URL}/user?username=1' OR '1'='1&email=test@example.com")
    print("SQLi:", r.status_code, r.json())

if __name__ == "__main__":
    test_health()
    test_endpoints()
    test_create_user()
    test_blocked_user_agent()
    test_sql_injection()
