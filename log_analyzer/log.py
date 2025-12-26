import os
from core.parser import parse_auth_log
from core.detectors import detect_bruteforce
from core.report import export_report

def load_log():
    default_path = "/var/log/auth.log"

    print("\nLog Source")
    print("1. Use default auth.log (/var/log/auth.log)")
    print("2. Provide custom log file path")

    choice = input("Choose option (1/2): ").strip()

    if choice == "1":
        path = default_path
    elif choice == "2":
        path = input("Enter full log file path: ").strip()
    else:
        print("Invalid choice.")
        return None

    if not os.path.exists(path):
        print("File does not exist.")
        return None

    try:
        with open(path, "r") as f:
            return f.read()
    except PermissionError:
        print("Permission denied. Try running with elevated privileges.")
        return None


def main():
    log_text = None
    entries = None

    while True:
        print("\n=== Suspicious Log Analyzer ===")
        print("1. Load auth.log")
        print("2. Detect brute-force attempts")
        print("3. Export report")
        print("4. Exit")

        choice = input("Select an option: ").strip()

        if choice == "1":
            log_text = load_log()
            if log_text:
                entries = parse_auth_log(log_text)
                print(f"Loaded log. Failed attempts found: {len(entries)}")

        elif choice == "2":
            if not entries:
                print("No log loaded. Load a log first.")
                continue

            results = detect_bruteforce(entries)
            if not results:
                print("No brute-force activity detected.")
            else:
                print("\nBrute-force attempts detected:")
                for r in results:
                    print(f"IP: {r['ip']} | Attempts: {r['attempts']}")

        elif choice == "3":
            if not entries:
                print("No data available to export.")
                continue

            results = detect_bruteforce(entries)
            export_report(results)
            print("Report exported to report.txt")

        elif choice == "4":
            print("Exiting.")
            break

        else:
            print("Invalid option. Try again.")


if __name__ == "__main__":
    main()
