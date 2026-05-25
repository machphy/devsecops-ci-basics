import re
from datetime import datetime, timedelta
from collections import defaultdict

LOG_FILE = "auth.log"
FAILED_THRESHOLD = 5
TIME_WINDOW_MINUTES = 2

log_pattern = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+).*(Failed password).*?(?P<time>\w+\s+\d+\s+\d+:\d+:\d+)'
)

failed_attempts = defaultdict(list)

def parse_time(time_str):
    return datetime.strptime(time_str, "%b %d %H:%M:%S")

def analyze_logs():
    with open(LOG_FILE, "r") as file:
        for line in file:
            match = log_pattern.search(line)
            if match:
                ip = match.group("ip")
                time = parse_time(match.group("time"))
                failed_attempts[ip].append(time)

def detect_bruteforce():
    suspicious_ips = []

    for ip, times in failed_attempts.items():
        times.sort()
        for i in range(len(times)):
            window = times[i:i + FAILED_THRESHOLD]
            if len(window) == FAILED_THRESHOLD:
                if window[-1] - window[0] <= timedelta(minutes=TIME_WINDOW_MINUTES):
                    suspicious_ips.append(ip)
                    break
    return suspicious_ips

def main():
    analyze_logs()
    attackers = detect_bruteforce()

    if attackers:
        print("[ALERT] Possible brute-force detected from:")
        for ip in attackers:
            print(f" - {ip}")
        exit(1)   # 🔐 DevSecOps security gate
    else:
        print("[OK] No brute-force activity detected")

if __name__ == "__main__":
    main()
