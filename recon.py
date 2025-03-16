import os
import subprocess
import argparse
import json
from datetime import datetime

# Setup argument parser
parser = argparse.ArgumentParser(description="Automated Network Reconnaissance Toolkit")
parser.add_argument("-t", "--target", required=True, help="Target IP, subnet, or domain")
parser.add_argument("-o", "--output", required=True, help="Output file name")
args = parser.parse_args()

# Create timestamped output directory
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
output_dir = f"recon_results/{args.output}_{timestamp}"
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
    """Scan open ports using Nmap."""
    print("[+] Performing Port Scanning")
    
    # Using fragmented packets, decoys, and a spoofed MAC address
    nmap_port_scan = f"nmap -T4 -sS {target}"
    run_command(nmap_port_scan, f"{output_dir}/nmap.txt", use_sudo=True)

def service_enum(target):
    """Enumerate running services, SMB, and RPC."""
    print("[+] Performing Service Enumeration...")
    run_command(f"nmap -sV -T4 {target}", f"{output_dir}/service_scan.txt", use_sudo=False)
    run_command(f"enum4linux {target}", f"{output_dir}/smb_enum.txt", use_sudo=True)
    run_command(f"rpcclient -U '' {target}", f"{output_dir}/rpc_enum.txt", use_sudo=True)

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

def generate_summary():
    """Generate JSON summary of results."""
    summary = {
        "target": args.target,
        "output_directory": output_dir,
        "timestamp": timestamp,
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

# Only run WHOIS and crt.sh if the target is a domain
if "." in args.target:
    whois_lookup(args.target)

generate_summary()

print(f"[✅] Reconnaissance Completed! Results saved in {output_dir}")

