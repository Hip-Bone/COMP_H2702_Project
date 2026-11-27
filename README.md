# COMP_H2702_Project

### Individual Project for the COMP H2702 module. Scenario D was chosen for this project. 

**All files should be kept in the same folder to ensure reliable behavior.**

A simple network exposure checker, essentially a script that scans 4 ports via passive port pinging in TCP. 
The scope is quite limited, only 4 specific ports and only 1 target IP address are authorised parameters. While this is
not within the scope and should never be done outside of a controlled test environment akin to what this script was designed for,
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

| Column 1 | Column 2 |
| :--- | :--- |
| Row 1, Item A | Row 1, Item B |
| Row 2, Item A | Row 2, Item B |
