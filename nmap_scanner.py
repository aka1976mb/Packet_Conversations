import subprocess
import sys
import re

def parse_nmap_output(nmap_output):
    """
    Parses the nmap output string and returns a Markdown formatted report.
    """
    report_parts = []

    # Get the target
    target_match = re.search(r"Nmap scan report for (.*)", nmap_output)
    if target_match:
        target = target_match.group(1).strip()
        report_parts.append(f"# Nmap Scan Report for {target}\n")

    # Get OS guess
    os_match = re.search(r"Aggressive OS guesses: (.*)", nmap_output)
    if os_match:
        os_guess = os_match.group(1).strip()
        report_parts.append(f"## OS Guess\n\n- {os_guess}\n")
    else:
        report_parts.append("## OS Guess\n\n- No aggressive OS guesses found.\n")


    # Extract the full port scanning section
    # Look for "PORT      STATE SERVICE    VERSION" up to "Aggressive OS guesses" or "Service Info"
    port_section_match = re.search(r"PORT\s+STATE\s+SERVICE\s+VERSION\n(.*?)(?:\nAggressive OS guesses:|\nService Info:|\nTRACEROUTE:|\nNmap scan report for|$)", nmap_output, re.DOTALL)

    if port_section_match:
        port_lines_block = port_section_match.group(1).strip()
        port_lines = port_lines_block.split('\n')
        
        if port_lines:
            report_parts.append("## Open Ports\n")
            report_parts.append("| Port | Service | Version |")
            report_parts.append("|---|---|---|")

            for line in port_lines:
                # Skip any lines that are part of nested outputs (like ssh-hostkey, http-methods, etc.)
                if line.strip().startswith('|') or line.strip().startswith('_'):
                    continue

                # Regex to capture: (port/proto) (state) (service) (version - optional, greedy)
                # Example: 22/tcp    open  ssh        OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
                # Example: 31337/tcp open  tcpwrapped
                match = re.search(r"(\S+)\s+open\s+(\S+)(?:\s+(.*))?", line)
                if match:
                    port_info = match.group(1)
                    service = match.group(2)
                    version = match.group(3).strip() if match.group(3) else "" # Handle optional version
                    report_parts.append(f"| {port_info} | {service} | {version} |")
                else:
                    # Fallback if regex doesn't match the expected format, add as a raw line
                    report_parts.append(f"| {line.strip()} | - | - |")
        else:
            report_parts.append("## Open Ports\n\nNo open ports found or output format not recognized within the port section.")
    else:
        report_parts.append("## Open Ports\n\nCould not find the port scanning section in nmap output.")
    
    return "\n".join(report_parts)

def run_nmap_scan(target):
    """
    Runs a simple nmap scan on the given target and prints a Markdown report.
    """
    if not target:
        print("Error: Please provide a target IP address or hostname.")
        return

    print(f"[*] Running nmap scan on {target}...")
    try:
        # -v for verbosity, -A for OS detection, version detection, script scanning, and traceroute
        result = subprocess.run([r'C:\Program Files (x86)\Nmap\nmap.exe', '-v', '-A', target], capture_output=True, text=True, check=True)
        
        markdown_report = parse_nmap_output(result.stdout)
        print(markdown_report)

    except FileNotFoundError:
        print("Error: nmap is not installed or not in your PATH.")
    except subprocess.CalledProcessError as e:
        print(f"Error during nmap scan: {e.stderr}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python nmap_scanner.py <target>")
        sys.exit(1)
    
    target_host = sys.argv[1]
    run_nmap_scan(target_host)