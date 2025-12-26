from collections import Counter

def detect_bruteforce(entries, threshold=5):
    """
    Detects IPs with failed login attempts >= threshold.
    """
    ip_counts = Counter(entry["ip"] for entry in entries)

    return [
        {"ip": ip, "attempts": count}
        for ip, count in ip_counts.items()
        if count >= threshold
    ]
def suspicious_usernames(entries):
    common_targets = {"root", "admin", "test"}
    found = set()

    for e in entries:
        if e["user"] in common_targets:
            found.add(e["user"])

    return list(found)
