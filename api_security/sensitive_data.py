# sensitive_data.py
# (Optional: for more advanced scanning, not used in this minimal demo)
def contains_sensitive_data(text: str) -> bool:
    keywords = ["SECRET", "TOKEN", "PASSWORD"]
    return any(keyword in text for keyword in keywords)
