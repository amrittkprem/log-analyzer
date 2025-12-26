def export_report(results, path="report.txt"):
    """
    Exports brute-force detection results to a text report.
    """
    with open(path, "w") as f:
        f.write("Log Analysis Report\n")
        f.write("===================\n\n")

        if not results:
            f.write("No brute-force activity detected.\n")
            return

        for r in results:
            f.write(f"IP: {r['ip']} | Attempts: {r['attempts']}\n")
