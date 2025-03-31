import os
import subprocess
import json
import argparse
import re
import threading

# Setup argument parser
parser = argparse.ArgumentParser(description="Automated Vulnerability Scanning")
parser.add_argument("-t", "--target", required=True, help="Target IP")
parser.add_argument("-o", "--output", required=True, help="Output directory from previous scan")
args = parser.parse_args()

output_dir = f"recon_results/{args.output}"
vuln_scan_dir = f"{output_dir}/vuln_scan"
os.makedirs(vuln_scan_dir, exist_ok=True)

def run_command(command, output_file, use_sudo=False):
    """Execute a command and save output to a file."""
    if use_sudo:
        command = f"sudo {command}"
    
    print(f"[*] Running: {command}")
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    
    os.makedirs(os.path.dirname(output_file), exist_ok=True)  # Ensure directory exists
    with open(output_file, "w") as f:
        f.write(result.stdout)

    if result.stderr:
        print(f"[!] Error: {result.stderr}")

    return result.stdout.strip()

def get_open_ports():
    """Extract open ports and service versions from service_scan.txt."""
    service_scan_file = f"{output_dir}/service_scan.txt"
    open_ports = []

    if not os.path.exists(service_scan_file):
        print("[!] No previous service scan found. Exiting.")
        return []

    with open(service_scan_file, "r") as f:
        for line in f.readlines():
            match = re.search(r"(\d+)/tcp\s+open\s+(\S+)\s+(.*)", line)
            if match:
                port, service, version = match.groups()
                version = version.strip() if version else "unknown"
                open_ports.append((int(port), service, version))
    
    print(f"[+] Found open ports and services: {open_ports}")
    return open_ports

def vulnerability_scan(target):
    """Perform Nmap vulnerability scanning."""
    print("[+] Running Nmap Vulnerability Scan...")
    run_command(f"nmap --script vuln {target}", f"{vuln_scan_dir}/nmap_vuln.txt", use_sudo=True)

def smb_enum(target):
    """Enumerate SMB shares and users."""
    print("[+] Running SMB Enumeration...")
    run_command(f"enum4linux -a {target}", f"{vuln_scan_dir}/smb_enum.txt", use_sudo=True)

def check_default_credentials(target, ports):
    """Check for weak or default credentials on common services."""
    print("[+] Checking for Default Credentials...")

    threads = []
    for port, service, _ in ports:
        output_file = f"{vuln_scan_dir}/{service}_default_creds.txt"
        
        if service == "ftp":
            command = f"nmap --script ftp-anon -p {port} {target}"
        elif service == "smb":
            command = f"nmap --script smb-vuln-ms17-010 -p {port} {target}"
        else:
            continue
        
        thread = threading.Thread(target=run_command, args=(command, output_file, True))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()

def exploit_search(target, ports):
    """Search for exploits using SearchSploit with only the version."""
    print("[+] Searching for Known Exploits...")

    threads = []
    for _, _, version in ports:
        if version == "unknown":
            continue  # Skip if no version info is available

        formatted_version = re.sub(r"\s+", " ", version.strip())  # Ensure proper spacing
        exact_query = f'"{formatted_version}"'  # Use only the version

        output_file = f"{vuln_scan_dir}/exploit_search_{formatted_version}.txt"
        command = f"searchsploit {exact_query}"  # Search using only the version

        thread = threading.Thread(target=run_command, args=(command, output_file, False))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

def metasploit_import(target):
    """Import Nmap results into Metasploit for further exploitation."""
    print("[+] Ensuring Metasploit is connected to the database...")

    # Check database connection status
    db_status_output = run_command("msfconsole -q -x 'db_status; exit'", "/dev/null", False)
    
    if "not connected" in db_status_output.lower():
        print("[!] Metasploit database not connected. Initializing it now...")
        run_command("msfdb init", "/dev/null", False)

    # Create Metasploit script
    print("[+] Importing Nmap results into Metasploit...")
    msf_commands = f"""
    db_connect msf:msf@127.0.0.1/msf
    db_nmap -sV -p- {target}
    hosts
    services
    vulns
    exit
    """
    
    msf_script = f"{vuln_scan_dir}/metasploit.rc"
    with open(msf_script, "w") as f:
        f.write(msf_commands)

    run_command(f"msfconsole -q -r {msf_script}", f"{vuln_scan_dir}/metasploit_output.txt", False)

def generate_report():
    """Generate a summary report."""
    summary = {
        "target": args.target,
        "output_directory": vuln_scan_dir,
        "modules_run": [
            "Nmap Vulnerability Scan",
            "SMB Enumeration",
            "Check Default Credentials",
            "Exploit Search",
            "Metasploit Import"
        ]
    }
    
    with open(f"{vuln_scan_dir}/summary.json", "w") as f:
        json.dump(summary, f, indent=4)

    print(f"[+] Summary saved to {vuln_scan_dir}/summary.json")

# Run vulnerability scans in parallel
open_ports = get_open_ports()
if open_ports:
    threads = [
        threading.Thread(target=vulnerability_scan, args=(args.target,)),
        threading.Thread(target=smb_enum, args=(args.target,)),
        threading.Thread(target=check_default_credentials, args=(args.target, open_ports)),
        threading.Thread(target=exploit_search, args=(args.target, open_ports)),
        #threading.Thread(target=metasploit_import, args=(args.target,))
    ]

    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    generate_report()
else:
    print("[!] No open ports found. Skipping vulnerability scanning.")

print(f"[✅] Scanning Completed! Results saved in {vuln_scan_dir}")

