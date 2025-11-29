import subprocess
import sys

def run_nmap_scan(target):
    """
    Runs a simple nmap scan on the given target.
    """
    if not target:
        print("Error: Please provide a target IP address or hostname.")
        return

    print(f"[*] Running nmap scan on {target}...")
    try:
        # -v for verbosity, -A for OS detection, version detection, script scanning, and traceroute
        result = subprocess.run([r'C:\Program Files (x86)\Nmap\nmap.exe', '-v', '-A', target], capture_output=True, text=True, check=True)
        print(result.stdout)
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
