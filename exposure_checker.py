# Local Network Exposure Checker

# Checks TCP connectivity to localhost ports, collects banners, makes HTTP requests, and produces reports in TXT and JSON

import os
import sys
import socket
import json
import http.client
import time
from datetime import datetime, timezone

ALLOWED_PORTS = {18080, 19090, 20001, 20002}

def load_targets(filepath): # Loads target address from text file

    try:
        with open(filepath, "r", encoding="utf-8") as file:
            targets = []
            for line in file:
                line = line.strip()
                if not line or line.startswith("#"): #if not line checks if the line is completely empty
                    continue
                targets.append(line)
            return targets or None
        
    except OSError:
        return None
    
def load_ports(filepath): # Loads ports from text file and returns a list of validated ports. Invalid lines are skipped with a warning

    try:
        with open(filepath, "r", encoding="utf-8") as file:
            ports = []
            for line in file:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.isdigit() and int(line) in ALLOWED_PORTS:
                    ports.append(int(line))
                else:
                    print(f"[WARNING] Port skipped (not in allowed ports): {line}")
            return ports or None
    except OSError:
        return None

def validate_target(target): # Ensures the target is local-only. Returns (ip), raises ValueError for invalid targets

    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror as ex:
        raise ValueError(f"Cannot resolve target '{target}': {ex}") from None

    if not ip.startswith("127."):
        raise ValueError(
            f"Target '{target}' resolves to {ip} (non-local). "
            "Only 127.x.x.x addresses are allowed by default."
        ) # Checks if the target address is in the localhost range of 127.X.X.X, if not 127.X.X.X it terminates the script in main()

    return ip

def check_port(target, port, timeout=3.0): # Checks the OPEN/CLOSED status of each port and records the results in a dictionary

    result = {
        "target": target,
        "port": port,
        "state": "CLOSED",
        "banner": None,
        "error": None,
    } # Populates banner and error keys with None so the dictionary structure stays consistent even if the requests fail

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((target, port))
            result["state"] = "OPEN" # Flips the port state to OPEN from the default CLOSED if socket connection is successful

            sock.settimeout(1.0)
            try:
                raw = sock.recv(256) # Reads up to 256 bytes from the socket to capture service banners
                if raw:
                    # Converts the raw bytes from the port into readable text and replaces unreadable characters
                    result["banner"] = raw.decode("utf-8", errors="replace").strip()
            except socket.timeout:
                pass
    except socket.timeout:
        result["error"] = (f"Connection timed out on port {port}")
    except ConnectionRefusedError:
        pass
    except OSError as ex:
        result["error"] = str(ex) # Inserts OSError message directly into the "error" paramterer in the "result" dictionary
                                  # manually set as a string, this is to prevent json.dump from crashing if the error pops up,
                                  # other instances of this error handler do not need this as "f" strings already auto-convert it

    return result

def check_all_ports(targets, ports): # Validates the targets and scans every (target, port) pair

    all_results = []

    for target in targets:
        try:
            resolved_ip = validate_target(target)
        except ValueError as ex:
            print(f"[BLOCKED] {ex}")
            continue # Skips scanning a target if local-only validation fails

        print(f"\n--- Scanning target: {target} (resolved to {resolved_ip}) ---")

        for port in ports: # Scans each allowed port on the validated localhost IP and stores the result
            result = check_port(resolved_ip, port)
            all_results.append(result)

    return all_results

def check_http_service(target, port = 18080): # Sends an HTTP GET request to http://<target>:18080/ and reports the status

    info = {
        "url": f"http://{target}:{port}/",
        "status_code": None,
        "content_type": None,
        "body_preview": None,
        "error": None,
    } # Populates all keys except url with None so the dictionary structure stays consistent even if the requests fail

    try:
        connection = http.client.HTTPConnection(target, port, timeout=5.0)
        connection.request("GET", "/") # Requests the root endpoint from the local HTTP service
        response = connection.getresponse()

        info["status_code"] = response.status
        info["content_type"] = response.getheader("Content-Type")
        body = response.read()
        info["body_preview"] = body.decode("utf-8", errors="replace").strip()[:200] # Decodes the raw bytes and caps preview at 200 characters
        connection.close()

    except http.client.HTTPException as ex:
        info["error"] = (f"HTTP error: {ex}")
    except OSError as ex:
        info["error"] = (f"Connection failed: {ex}")

    return info

def calculate_risk(results, http_info): # Simple scan loop for risk score calculation and severity interpretation

    # Severity Score System (0-100, lower is safer):
      # Each OPEN port adds 15 points
      # Port 20002 open -> +45 (unexpected)
      # HTTP service healthy -> -10 (bonus for healthy HTTP service)
    
    open_count = 0
    score = 0

    for result in results: # For loop that runs for each entry in the port list
        if result["state"] == "OPEN":
            open_count += 1 # Stores the amount of ports for later use
            if result["port"] == 20002:
                score += 45 # Unexpected open port carries a heavy point weight
            else:
                score += 15 # Expectable local service

    if http_info.get("status_code") == 200: # Bonus: healthy HTTP service verification
        score -= 10

    score = max(0, min(score, 100)) # Ensures that the score stays within the range of 0 to 100

    if score <= 30:
        level = "LOW"
    elif score <= 55:
        level = "MEDIUM"
    else:
        level = "HIGH"

    return {
        "open_ports": open_count,
        "total_ports": len(results),
        "closed_ports": len(results) - open_count,
        "risk_score": score,
        "interpretation": level,
    }

def generate_report(results, http_info, risk): # Builds a structured report and writes TXT / JSON files

    timestamp = datetime.now(timezone.utc).strftime("%d-%m-%Y %H:%M UTC") # Dynamically checks the time, based on the computer clock
    margin = "=" * 117 # Quick copy-friendly margin to make printed report neater, 117 "=" fits all the text in

    scan_lines = []
    # Formats each port result into an aligned line, appending banner or error details if present
    for result in results:
        line = (f"  Port {result['port']:>5}  {result['state']:>7} | Target: {result['target']}")
        if result.get("banner"):
            line += (f" | Banner: {result['banner']}")
        if result.get("error"):
            line += (f" | Error: {result['error']}")
        scan_lines.append(line)

    if http_info.get("status_code"): # Formats HTTP response details if reachable or falls back to the error message
        http_section = (
            f"  URL:          {http_info['url']}\n"
            f"  Status code:  {http_info['status_code']}\n"
            f"  Content-Type: {http_info.get('content_type', 'N/A')}\n"
            f"  Body preview: {(http_info.get('body_preview') or '').strip()}"
        )

    else:
        http_section = (f"  Error: {http_info.get('error', 'Unknown')}")

    text_report = (f"""{margin}
  LOCAL NETWORK EXPOSURE REPORT
  Generated: {timestamp}
{margin}

--- PORT SCAN RESULTS ---
{"\n".join(scan_lines)}

--- HTTP SERVICE (port 18080) ---
{http_section}

--- RISK SUMMARY ---
  Open ports    : {risk['open_ports']}/{risk['total_ports']}
  Closed ports  : {risk['closed_ports']}/{risk['total_ports']}
  Risk score    : {risk['risk_score']}/100
  Interpretation: {risk['interpretation']}

--- SECURITY INTERPRETATION ---
  # This section is not available in the JSON file. It only contains the technical data. #
  An OPEN port indicates that a TCP listener is accepting connections on that specific port.
  This does NOT mean it is malicious or a vulnerability by itself. It may have legitimate reasons for being open.

  A high exposure rating is also not a smoking gun by itself; port 20002 may sometimes
  be open for legitimate reasons such as temporary local testing, developer debugging,
  or an internal microservice like a health-check endpoint. Verify manually before treating it as a security issue.

{margin}
--- END OF REPORT ---
{margin}
""") # Prints out a concise report with explanations, and saves the report into .txt and .json files

    # Saves both report files in the same folder as the script
    base_dir = os.path.dirname(os.path.abspath(__file__))
    txt_path = os.path.join(base_dir, "exposure_report.txt")
    json_path = os.path.join(base_dir, "exposure_report.json")

    report_data = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "scan_results": results,
        "http_service": http_info,
        "risk_summary": risk,
    } # Dictionary that gives the JSON file the proper structure formatting

    try:
        with open(txt_path, "w", encoding="utf-8") as file:
            file.write(text_report)

        print(f"\n[OK] Text report written to {txt_path}")

        with open(json_path, "w", encoding="utf-8") as file:
            json.dump(report_data, file, indent = 2) # indent = 2 helps with report readability by splitting the outputs into multiple lines

        print(f"[OK] JSON report written to {json_path}")

    except OSError as ex:
        print(f"\n[WARNING] Could not write report files: {ex}")

    return text_report

def main(): # Executes 6 step procedure to check the local network exposure, uses all the functions above
    print()
    print("LOCAL NETWORK EXPOSURE CHECKER")
    print("Checking only localhost (127.0.0.1)")
    print()

    script_dir = os.path.dirname(os.path.abspath(__file__)) # Finds the folder where this script is saved, so all files are located reliably

    time.sleep(1) # 1 second pauses make the terminal output easier to follow and digest

    print("\n[1] Loading targets and ports from files...")
    targets = load_targets(os.path.join(script_dir, "targets.txt"))
    if targets is None:
        print("File 'targets.txt' not found or empty, terminating.")
        return

    ports = load_ports(os.path.join(script_dir, "ports.txt"))
    if ports is None:
        print("File 'ports.txt' not found or empty, terminating.")
        return # Step 1 terminates the script if any of the 2 files are missing and/or empty

    print(f"  Targets : {targets}")
    print(f"  Ports   : {ports}")
    
    time.sleep(1)

    print("\n[2] Validating if target is local...")
    for target in targets:
        try:
            resolved = validate_target(target)
            print(f"  {target} -> {resolved} [LOCAL]")
        except ValueError as ex:
            print(f"  {target} -> [BLOCKED] {ex}")
            print("Terminating Network Exposure Check.")
            return
        
    time.sleep(1)

    print("\n[3] Scanning ports...")
    results = check_all_ports(targets, ports)

    for result in results:
        banner_preview = (f' | Banner: "{result["banner"]}"' if result.get("banner") else "")
        print(f"  Port {result['port']:>5} : {result['state']}{banner_preview}") # Appends a banner string if the port returned one

    time.sleep(1)

    print("\n[4] Running HTTP test service...")
    http_info = check_http_service("127.0.0.1") # Sends an HTTP GET request to port 18080 and captures the status and headers
    print(
        f"  {http_info['url']} -> "
        f"{http_info.get('status_code', 'N/A')} | "
        f"{http_info.get('content_type', '')}"
    )

    time.sleep(1)

    print("\n[5] Calculating risk...")
    risk = calculate_risk(results, http_info)
    print(
        f"  Open: {risk['open_ports']} | "
          f"Closed: {risk['closed_ports']} | "
          f"Score: {risk['risk_score']}/100 ({risk['interpretation']})"
    ) # Evaluates open/closed ports and HTTP health status to produce a 0-100 risk summary, LOW-MEDIUM-HIGH

    time.sleep(1)

    print("\n[6] Generating reports...")
    report_text = generate_report(results, http_info, risk)

    print("\n" + report_text)

    return

if __name__ == "__main__": # Ensures main() only runs when this script is executed in this .py file
    sys.exit(main())
