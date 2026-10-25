import urllib.request
import urllib.error
from datetime import datetime

def scan_website(url):
    report = []

    report.append("VULNERABILITY SCANNER REPORT")
    report.append("Date: " + str(datetime.now()))
    report.append("Target: " + url)
    report.append("-" * 45)

    if not url.startswith("https://"):
        report.append("[HIGH] Website is not using HTTPS.")
        report.append("Fix: Configure HTTPS with a valid TLS certificate.")
    else:
        report.append("[INFO] HTTPS is being used.")

    try:
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "MiniProjectScanner/1.0"}
        )

        with urllib.request.urlopen(request, timeout=10) as response:
            headers = response.headers

            checks = {
                "Content-Security-Policy":
                    "Helps reduce certain injection risks.",
                "X-Content-Type-Options":
                    "Helps prevent MIME-type sniffing.",
                "Strict-Transport-Security":
                    "Helps enforce HTTPS in supporting browsers."
            }

            report.append("HTTP Status: " + str(response.status))

            for header, purpose in checks.items():
                if header in headers:
                    report.append("[PASS] " + header + " found.")
                else:
                    report.append("[REVIEW] " + header + " is missing.")
                    report.append("Purpose: " + purpose)

    except (urllib.error.URLError, TimeoutError, ValueError) as error:
        report.append("[ERROR] Could not scan website: " + str(error))

    with open("vulnerability_report.txt", "w") as file:
        file.write("\n".join(report))

    print("\n".join(report))
    print("\nReport saved as vulnerability_report.txt")


if __name__ == "__main__":
    website = input("Enter an authorized website URL: ").strip()
    scan_website(website)