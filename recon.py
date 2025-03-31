import os
import subprocess
import argparse
import json
from datetime import datetime
import re
import socket
import requests

# Setup argument parser
parser = argparse.ArgumentParser(description="Automated Network Reconnaissance Toolkit")
parser.add_argument("-t", "--target", required=True, help="Target IP, subnet, or domain")
parser.add_argument("-o", "--output", required=True, help="Output file name")
args = parser.parse_args()

output_dir = f"recon_results/{args.output}"
os.makedirs(output_dir, exist_ok=True)

def run_command(command, output_file, use_sudo=False):
    """Execute a command with optional sudo and save the output to a file."""
    if use_sudo:
        command = f"sudo {command}"
    
    print(f"[*] Running: {command}")
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    
    # Save output to file
    with open(output_file, "w") as f:
        f.write(result.stdout)

    if result.stderr:
        print(f"[!] Error running {command}: {result.stderr}")

    return result.stdout.strip()

def network_discovery(target):
    """Identify active hosts using Nmap."""
    print("[+] Performing Network Discovery...")
    run_command(f"nmap -sn {target}", f"{output_dir}/live_hosts.txt")

def port_scan(target):
    """Scan open ports using Nmap and return structured results."""
    print("[+] Performing Port Scanning...")
    
    nmap_output = run_command(f"nmap -T4 -Pn -sS {target}", f"{output_dir}/nmap.txt", use_sudo=True)
    
    open_ports = []
    for line in nmap_output.splitlines():
        match = re.search(r"(\d+)/tcp\s+(\w+)\s+(\S+)", line)  # Extract port, state, and service
        if match:
            port, state, service = match.groups()
            print(f"[*] Port {port}: {state} ({service})")
            if state == "open":
                open_ports.append(int(port))

    return open_ports


def service_enum(target):
    """Enumerate running services, SMB, and RPC."""
    print("[+] Performing Service Enumeration...")
    run_command(f"nmap -sV -T4 {target}", f"{output_dir}/service_scan.txt", use_sudo=False)
    run_command(f"enum4linux {target}", f"{output_dir}/smb_enum.txt", use_sudo=True)

def os_detection(target):
    """Identify OS details."""
    print("[+] Detecting OS...")
    run_command(f"nmap -O {target}", f"{output_dir}/os_detection.txt", use_sudo=True)

def topology_mapping(target):
    """Map network topology using traceroute."""
    print("[+] Mapping Network Topology...")
    run_command(f"traceroute {target}", f"{output_dir}/traceroute.txt")

def passive_recon(target):
    """Perform passive information gathering using OSINT tools."""
    print("[+] Conducting Passive Reconnaissance...")
    domain = target  # Assuming target is a domain
    run_command(f"dnsrecon -d {domain}", f"{output_dir}/dns_recon.txt")

def whois_lookup(target):
    """Perform WHOIS lookup (only for domains)."""
    print("[+] Performing WHOIS Lookup...")
    run_command(f"whois {target}", f"{output_dir}/whois.txt")
    
def dig_enum(target):
    """Perform WHOIS lookup (only for domains)."""
    print("[+] Performing Dig Lookup...")
    run_command(f"dig ANY {target}", f"{output_dir}/Dig_ANY.txt")
    run_command(f"dig ALL {target}", f"{output_dir}/Dig_ALL.txt")

def banner_grab(target):
    """Perform WHOIS lookup (only for domains)."""
    print("[+] Grabbing Banners...")
    run_command(f"nmap -sV --script=banner {target}", f"{output_dir}/Banner_grab.txt")
    
def crtsh_lookup(target):
    """Fetch subdomains using crt.sh."""
    print("[+] Querying crt.sh for subdomains...")
    query = f"https://crt.sh/?q={target}&output=json"
    try:
        response = requests.get(query, timeout=10)
        if response.status_code == 200:
            data = response.json()
            subdomains = {entry["name_value"] for entry in data}
            with open(f"{output_dir}/crtsh.txt", "w") as f:
                f.write("\n".join(subdomains))
            print(f"[+] Found {len(subdomains)} subdomains")
        else:
            print("[!] crt.sh query failed")
    except Exception as e:
        print(f"[X] Error querying crt.sh: {e}")

    

def generate_summary():
    """Generate JSON summary of results."""
    summary = {
        "target": args.target,
        "output_directory": output_dir,
        "modules_run": [
            "Network Discovery",
            "Port Scanning with Firewall Evasion",
            "Service Enumeration (SMB & RPC)",
            "OS Detection",
            "Network Mapping",
            "WHOIS Lookup",
            "Passive Recon"
        ]
    }
    with open(f"{output_dir}/summary.json", "w") as f:
        json.dump(summary, f, indent=4)
    print(f"[+] Summary saved to {output_dir}/summary.json")

# Run the recon steps
network_discovery(args.target)
port_scan(args.target)
service_enum(args.target)
os_detection(args.target)
topology_mapping(args.target)
passive_recon(args.target)
dig_enum(args.target)
banner_grab(args.target)
crtsh_lookup(args.target)
# Only run WHOIS and crt.sh if the target is a domain
if "." in args.target:
    whois_lookup(args.target)

generate_summary()

print(f"[✅] Reconnaissance Completed! Results saved in {output_dir}")

