import re

def parse_auth_log(log_text):
    """
    Parses Linux auth.log failed login attempts.
    Returns a list of dicts with IP and username.
    """
    entries = []

    pattern = re.compile(
        r'Failed password for (invalid user )?(?P<user>\w+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'
    )

    for line in log_text.splitlines():
        match = pattern.search(line)
        if match:
            entries.append({
                "user": match.group("user"),
                "ip": match.group("ip")
            })

    return entries
