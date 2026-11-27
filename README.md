# COMP_H2702_Project

### Individual Project for the COMP H2702 module. Scenario D was chosen for this project. 

**All files should be kept in the same folder to ensure reliable behavior.**

A simple network exposure checker script that scans 4 ports via passive port pinging in TCP and reports their status as OPEN/CLOSED. 
Generates a report to both .txt and .json formats. The scope is quite limited as only 4 specific ports and only 1 specific IP address (localhost) are authorised targets.

## How to Run: ##
1.  If downloading as a .zip, extract the folder anywhere, if downloading each file, create a common folder for them.
2.	Open Terminal 1 in the project folder and start the test service python file: `python local_test_services.py`.
3.	Open Terminal 2 in the same folder and run the exposure checker python file: `python exposure_checker.py`.
4.	Review the terminal output and the generated `exposure_report.txt` / `exposure_report.json` files.


While this is
**not** within the scope and should never be done outside of a controlled test environment akin to what this script was designed for,
the script *can* technically be modified to allow different ports or IP addresses by changing the integers inside the `ALLOWED_PORTS` constant 
and editing the following code block:
```python
  if not ip.startswith("127."):
      raise ValueError(
          f"Target '{target}' resolves to {ip} (non-local). "
          "Only 127.x.x.x addresses are allowed by default."
          )
```
Simply edit `("127.")` to a different address like 192.168.X.X or any other desired address. Then update or remove 
the `"Only 127.x.x.x addresses are allowed by default"` disclaimer or change it to the new whitelisted address.

Additionally, the `check_http_service(target, port = 18080)` and `calculate_risk(results, http_info)` functions would also have to be changed, specifically:
1. The permitted port inside the `check_http_service(port = 18080)` function parameter.
2. The `if result["port"] == 20002` code block inside the `for result in results` in the `calculate_risk` function.
3. Optional change to the port score weight immediately after above code block: `score += 45`.

## Requirements: ##

**Python 3.14 is recommended for this script.**
**No external third-party packages required.**
**The script is built entirely with the Python 3 standard library:**

| modules: |
| :--- |
| `import os` |
| `import sys` |
| `import socket` |
| `import json` |
| `import http.client` |
| `import time` |
| `from datetime import datetime, timezone` |

## Files ## 
•	`targets.txt`: Target host address (restricted to 127.0.0.1).
•	`ports.txt`: Fixed test ports (18080, 19090, 20001, 20002).
•	`local_test_services.py`: Supplied local TCP banner listeners and HTTP test service on port 18080.
•	`exposure_checker.py`: The network exposure checker script file.

