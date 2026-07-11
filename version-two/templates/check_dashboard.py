with open(r"C:\Users\morbi\.gemini\antigravity\scratch\aegis-ics\version-two\app.py", "r", encoding="utf-8") as f:
    lines = f.readlines()
    for idx, line in enumerate(lines):
        if "def generate_incident_report_pdf" in line:
            print(f"Line {idx+1}: {line.strip()}")
