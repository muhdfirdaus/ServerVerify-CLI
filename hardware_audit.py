#!/usr/bin/env python3
"""
hardware_audit.py

A Python 3 script developed for a Senior Test Engineer demonstration.
This script performs a system hardware audit on Linux systems (e.g., Ubuntu). 

It gathers CPU, memory, and disk usage information, compares actual CPU 
cores and RAM against predefined 'Expected' values, and generates both 
a log file and a JSON output report for further data analysis.

Security & Best Practices included:
- PEP8 compliant
- Avoiding `shell=True` in subprocess calls to prevent shell injection.
- Robust exception handling across execution and data parsing segments.
- Meaningful type hints, logging, and documentation comments.
"""

import json
import logging
import subprocess
import sys
from typing import Dict, List, Any

# =====================================================================
# Configuration & Expected Values
# =====================================================================
EXPECTED_CPU_CORES = 4
EXPECTED_RAM_MB = 8192  # 8 GB (8192 MB)

LOG_FILE = "test_results.log"
JSON_OUTPUT_FILE = "hardware_audit.json"

# Configure standard logging to output to both a file and standard out
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)


def run_command(command: List[str]) -> str:
    """
    Executes a system shell command and returns its standard output.
    
    Args:
        command (List[str]): A list representing the command and its arguments.
        
    Returns:
        str: The stripped stdout of the command, or an empty string if it fails.
    """
    command_str = " ".join(command)
    logging.debug(f"Executing command: {command_str}")
    
    try:
        # capture_output=True automatically sets stdout and stderr to subprocess.PIPE
        # text=True decodes the byte payload to a string
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True
        )
        return result.stdout.strip()
    
    except FileNotFoundError:
        logging.error(f"Command not found: '{command[0]}'. Is this running on Linux?")
        return ""
    except subprocess.CalledProcessError as e:
        logging.error(f"Command '{command_str}' failed with exit code {e.returncode}.")
        logging.error(f"Error Details: {e.stderr.strip()}")
        return ""
    except Exception as e:
        logging.critical(f"An unexpected error occurred while executing '{command_str}': {e}")
        return ""


def audit_cpu() -> Dict[str, Any]:
    """
    Gathers CPU information using the 'lscpu' command and compares it.
    
    Returns:
        Dict: Contains the actual number of CPU cores and a comparison status.
    """
    logging.info("Starting CPU audit...")
    cpu_info = {"actual_cores": 0, "expected_cores": EXPECTED_CPU_CORES, "status": "FAIL"}
    
    output = run_command(["lscpu"])
    if output:
        # Iterate over output lines to find the CPU socket/core count
        for line in output.splitlines():
            if line.startswith("CPU(s):"):
                parts = line.split(":")
                if len(parts) == 2:
                    try:
                        actual_cores = int(parts[1].strip())
                        cpu_info["actual_cores"] = actual_cores
                        
                        # Validate against expectations
                        if actual_cores >= EXPECTED_CPU_CORES:
                            cpu_info["status"] = "PASS"
                            logging.info(f"CPU Check PASSED: Found {actual_cores} Core(s). (Expected: >={EXPECTED_CPU_CORES})")
                        else:
                            logging.warning(f"CPU Check FAILED: Found {actual_cores} Core(s). (Expected: >={EXPECTED_CPU_CORES})")
                        
                        return cpu_info  # Exit early once successfully parsed
                    
                    except ValueError:
                        logging.error("Failed to parse CPU core count as an integer.")
                        
    logging.error("Failed to extract CPU information from 'lscpu'.")
    return cpu_info


def audit_memory() -> Dict[str, Any]:
    """
    Gathers Memory information using the 'free -m' command and compares it.
    
    Returns:
        Dict: Contains the actual RAM amount and a comparison status.
    """
    logging.info("Starting Memory audit...")
    mem_info = {"actual_ram_mb": 0, "expected_ram_mb": EXPECTED_RAM_MB, "status": "FAIL"}
    
    output = run_command(["free", "-m"])
    if output:
        for line in output.splitlines():
            if line.startswith("Mem:"):
                # Split based on arbitrary whitespace
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        actual_ram = int(parts[1].strip())
                        mem_info["actual_ram_mb"] = actual_ram
                        
                        # Apply 10% leeway since OS kernel reserves some RAM
                        acceptable_ram = EXPECTED_RAM_MB * 0.90
                        if actual_ram >= acceptable_ram:
                            mem_info["status"] = "PASS"
                            logging.info(f"Memory Check PASSED: Found {actual_ram} MB. (Expected: ~{EXPECTED_RAM_MB} MB)")
                        else:
                            logging.warning(f"Memory Check FAILED: Found {actual_ram} MB. (Expected: ~{EXPECTED_RAM_MB} MB)")
                            
                        return mem_info
                    
                    except ValueError:
                        logging.error("Failed to parse Memory amount as an integer.")
                        
    logging.error("Failed to extract Memory information from 'free -m'.")
    return mem_info


def audit_disks() -> List[Dict[str, str]]:
    """
    Gathers block device information using the 'lsblk' command to pinpoint disks.
    
    Returns:
        List[Dict]: A list of primary disks containing their names and sizes.
    """
    logging.info("Starting Disk audit...")
    disks = []
    
    # We query lsblk requesting only physical disks to limit clutter
    output = run_command(["lsblk", "-d", "-o", "NAME,SIZE,TYPE"])
    if output:
        lines = output.splitlines()
        
        # Skip the header row
        for line in lines[1:]:
            parts = line.split()
            if len(parts) == 3:
                name, size, dev_type = parts
                if dev_type == "disk":
                    disks.append({
                        "name": name,
                        "size": size
                    })
                    
        logging.info(f"Found {len(disks)} primary disk(s).")
    else:
        logging.error("Failed to extract disk information from 'lsblk'.")
        
    return disks


def generate_json_report(data: Dict[str, Any], filename: str = JSON_OUTPUT_FILE) -> None:
    """
    Writes the collected auditing data safely to a JSON file.
    
    Args:
        data (Dict): The payload containing the system audit results.
        filename (str): The destination file.
    """
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        logging.info(f"JSON analysis report successfully generated: '{filename}'")
    except IOError as e:
        logging.error(f"IOError encountered while writing JSON report to '{filename}': {e}")
    except Exception as e:
        logging.critical(f"Unexpected error generating JSON report: {e}")


def main() -> None:
    """
    The main execution wrapper that fires off all checks.
    """
    logging.info("==========================================")
    logging.info("Hardware Audit Sequence Initiated")
    logging.info("==========================================")
    
    # Bundle result executions
    audit_results = {
        "cpu_audit": audit_cpu(),
        "memory_audit": audit_memory(),
        "disk_audit": audit_disks(),
    }
    
    # Post execution JSON reporting
    generate_json_report(audit_results)
    
    logging.info("==========================================")
    logging.info("Hardware Audit Sequence Completed")
    logging.info("==========================================")


if __name__ == "__main__":
    main()
