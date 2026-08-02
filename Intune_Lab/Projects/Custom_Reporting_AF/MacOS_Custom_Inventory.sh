#!/bin/bash
set -euo pipefail
set -o errtrace
#
#----------------------------------------------
# CONFIGURATION
#----------------------------------------------
# A substring we use to find the private key
IDENTITY="<LEAF CERT NAME>"
# URL (for JSON submission)
URL="<URL>"
# LOG FILE
LogFile="<FULL LOG PATH>"
#----------------------------------------------
# Logging initialization
#----------------------------------------------
# Delete the existing log if it exists
[[ -n "$LogFile" && -f "$LogFile" ]] && rm -f "$LogFile" 2>/dev/null || true
# Function to write to the log file for code brevity
Write_Log() {
    [[ -n "${1:-}" && -n "${2:-}" ]] || return
    printf "%s\t%s\n" "$(date +"%Y-%m-%d %H:%M:%S")" "$2" >> "$1"
}
#----------------------------------------------
# Trap functions - Error trapping and logging
#----------------------------------------------
# error_handler - Writes log info
error_handler() {
    local exit_code="$1"
    local line_no="$2"
    local cmd="$BASH_COMMAND"
    Write_Log "$LogFile" "RUNTIME ERROR: Command '$cmd' failed at line $line_no with exit code $exit_code"
    echo "ERROR: Command '$cmd' failed at line $line_no (exit $exit_code)" >&2
    exit "$exit_code"
}
# error_exit - Log an error message and terminate
error_exit() {
    local message="$1"
    Write_Log "$LogFile" "ERROR: $message"
    echo "ERROR: $message" >&2
    exit 1
}
# Any error gets trapped and logged here
trap 'error_handler $? $LINENO' ERR
###############################################
# Locate our certificate
###############################################
# Locate matching SSL client identities in System.keychain
MATCHES=$(security find-identity -p ssl-client -v /Library/Keychains/System.keychain | awk -v id="$IDENTITY" -F\" '/\"/ && $2 ~ id {print $2}')
# If we didn't find anything, log it and exit with an error
if [[ -z "$MATCHES" ]]; then
    Write_Log "$LogFile" "No matching SSL client identities found for substring: $IDENTITY"
    exit 1
fi
# Iterate through matches and select the first non-expired certificate
SELECTED_IDENTITY=""
while IFS= read -r NAME; do
    # Extract certificate PEM
    CERT=$(security find-certificate -c "$NAME" -p /Library/Keychains/System.keychain)
    # Extract NotAfter date
    NOT_AFTER=$(echo "$CERT" | openssl x509 -noout -enddate | cut -d= -f2)
    # Convert to epoch
    EXPIRY_EPOCH=$(date -j -f "%b %d %H:%M:%S %Y %Z" "$NOT_AFTER" +"%s")
    NOW_EPOCH=$(date +"%s")
    if (( EXPIRY_EPOCH > NOW_EPOCH )); then
        SELECTED_IDENTITY="$NAME"
        break
    fi
done <<< "$MATCHES"
# If there are no valid certificates, log the error and exit
if [[ -z "$SELECTED_IDENTITY" ]]; then
    Write_Log "$LogFile" "All matching identities are expired."
    exit 1
fi
# Log the success
Write_Log "$LogFile" "Using identity: $SELECTED_IDENTITY"
###############################################
# Begin Inventory script
###############################################
#----------------------------
# Detect Intune Device Name
#----------------------------
MANAGEDDEVICENAME=$(Hostname)
Write_Log "$LogFile" "ManagedDeviceName: $MANAGEDDEVICENAME"
#
#----------------------------
# Detect Intune Device ID
#----------------------------
MANAGEDDEVICEID=$(
security find-certificate -a -Z /Library/Keychains/System.keychain |
awk -F= '/issu/ && /MICROSOFT INTUNE MDM DEVICE CA/ {getline; print $2}' |
tr -d '"' |
sort -u
)
Write_Log "$LogFile" "ManagedDeviceId: $MANAGEDDEVICEID"
#
#----------------------------
# Detect console user
#----------------------------
CURRENT_USER=$(stat -f "%Su" /dev/console)
Write_Log "$LogFile" "Current User: $CURRENT_USER"
#
#----------------------------
# XProtect Status
#----------------------------
# Define potential file paths based on macOS versioning structures
XP_NEW_PATH="/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents"
XP_LEGACY_PATH="/System/Library/CoreServices/XProtect.bundle/Contents"
# Check which path exists on the host machine and extract the versions
if [[ -d "$XP_NEW_PATH" ]]; then
    INFO="$XP_NEW_PATH/Info.plist"
    META="$XP_NEW_PATH/Resources/XProtect.meta.plist"
    if [[ -f "$INFO" ]]; then
        XP_VERSION=$(defaults read "$INFO" CFBundleShortVersionString 2>/dev/null)
    else
        XP_VERSION="Unknown"
    fi
    if [[ -f "$META" ]]; then
        XP_META=$(plutil -p "$META" | grep "\"Version\"" | awk -F' ' '{print $3}')
    else
        XP_META="Unknown"
    fi
elif [[ -d "$XP_LEGACY_PATH" ]]; then
    INFO="$XP_LEGACY_PATH/Info.plist"
    META="$XP_LEGACY_PATH/Resources/XProtect.meta.plist"
    if [[ -f "$INFO" ]]; then
        XP_VERSION=$(defaults read "$INFO" CFBundleShortVersionString 2>/dev/null)
    else
        XP_VERSION="Unknown"
    fi
    if [[ -f "$META" ]]; then
        XP_META=$(plutil -p "$META" | grep "\"Version\"" | awk -F' ' '{print $3}')
    else
        XP_META="Unknown"
    fi
else
    XP_VERSION="Unknown (XProtect file not found)"
    XP_META="Unknown (XProtect file not found)"
fi
Write_Log "$LogFile" "XProtect Version: $XP_VERSION"
Write_Log "$LogFile" "XProtect Meta Version: $XP_META"
if command -v XProtect >/dev/null 2>&1; then
    # Real-time protection state
    XP_LAUNCH_SCAN=$(XProtect status | awk -F': ' '/launch/{print $2}')
    XP_BACKGROUND_SCAN=$(XProtect status | awk -F': ' '/background/{print $2}')
    #
    Write_Log "$LogFile" "XProtect launch scan: $XP_LAUNCH_SCAN"
    Write_Log "$LogFile" "XProtect background scan: $XP_BACKGROUND_SCAN"
else
    Write_Log "$LogFile" "XProtect not found"
fi
#
#----------------------------
# FileVault Data Volume Encryption
#----------------------------
FILEVAULT_STATUS=$(diskutil apfs list -plist | plutil -convert json -o - - |
jq -r '
[
  .Containers[].Volumes[]
  | select(.Roles[]? == "Data")
  | {
      Name: .Name,
      FileVault: (
        if .Encrypted == true then
          "Encrypted"
        elif .EncryptionProgress != null then
          "Encryption In Progress"
        else
          "Not Encrypted"
        end
      )
    }
  | "\(.Name);\(.FileVault)"
]
| join("|")
')
Write_Log "$LogFile" "FileVault: $FILEVAULT_STATUS"
#----------------------------
# Secure Token Status
#----------------------------
if [[ "$CURRENT_USER" == "root" || -z "$CURRENT_USER" ]]; then
    SECURE_TOKEN_STATUS="No console user"
else
    TOKEN_RESULT=$(sysadminctl -secureTokenStatus "$CURRENT_USER" 2>&1)
    if echo "$TOKEN_RESULT" | grep -qi "ENABLED"; then
        SECURE_TOKEN_STATUS="Enabled"
    elif echo "$TOKEN_RESULT" | grep -qi "DISABLED"; then
        SECURE_TOKEN_STATUS="Disabled"
    else
        SECURE_TOKEN_STATUS="Unknown"
    fi
fi
Write_Log "$LogFile" "Secure Token Status: $SECURE_TOKEN_STATUS"
#----------------------------
# Bootstrap Token Status
#----------------------------
BOOTSTRAP_RESULT=$(profiles status -type bootstraptoken 2>&1)
if echo "$BOOTSTRAP_RESULT" | grep -Eqi "escrowed.*YES|YES.*escrowed"; then
    BOOTSTRAP_TOKEN_STATUS="Escrowed"
elif echo "$BOOTSTRAP_RESULT" | grep -Eqi "escrowed.*NO|NO.*escrowed"; then
    BOOTSTRAP_TOKEN_STATUS="Not Escrowed"
else
    BOOTSTRAP_TOKEN_STATUS="Unknown"
fi
Write_Log "$LogFile" "Bootstrap Token Status: $BOOTSTRAP_TOKEN_STATUS"
#----------------------------
# Mac Address (MAC0-MACx) Physical network adapter and MAC address "Nutanix VirtIO Ethernet Adapter #2|50:6B:8D:CA:DB:93"
#----------------------------
i=0
while read -r line; do
    if [[ "$line" == Hardware\ Port:* ]]; then
        hwport="${line#Hardware Port: }"
        mac=""
    elif [[ "$line" == Ethernet\ Address:* ]]; then
        mac="${line#Ethernet Address: }"
        declare "MAC$i"="$hwport|$mac"
        (( i++ ))
    fi
done < <(networksetup -listallhardwareports)
# Ensure MAC0–MAC4 exist
while [ "$i" -lt 5 ]; do
    declare "MAC$i"=""
    (( i++ ))
done
Write_Log "$LogFile" "MAC Addresses enumerated."
#----------------------------
# Build Date
#----------------------------
BuildEpoch=$(stat -f "%m" /var/db/.AppleSetupDone)
BuildDate=$(date -jf "%s" "$BuildEpoch" +"%m/%d/%Y, %I:%M:%S %p")
Write_Log "$LogFile" "Build Date: $BuildDate"
#
#----------------------------
# Last Boot Time
#----------------------------
LastBoot=$(sysctl -n kern.boottime | awk '{print $4}' | sed 's/,//')
LastBootTime=$(date -jf "%s" "$LastBoot" +"%m/%d/%Y, %I:%M:%S %p")
Write_Log "$LogFile" "Last Boot Time: $LastBootTime"
#
#----------------------------
# Build json
#----------------------------
jsonData=$(jq -n \
    --arg ManagedDeviceName "$MANAGEDDEVICENAME" \
    --arg ManagedDeviceID "$MANAGEDDEVICEID" \
    --arg DefenderState "" \
    --arg DefenderStart "" \
    --arg DefSpySigAge "" \
    --arg DefNisSigAge "" \
    --arg DefAVSigAge "" \
    --arg DefAMEngine "" \
    --arg BitlockerState "" \
    --arg BitlockerStart "" \
    --arg BitEncrypted "" \
    --arg BitEncryption "" \
    --arg BitProtected "" \
    --arg BitProtector "" \
    --arg XProtect_Version "$XP_VERSION" \
    --arg XProtect_Meta "$XP_META" \
    --arg XProtect_Launch "$XP_LAUNCH_SCAN" \
    --arg XProtect_Background "$XP_BACKGROUND_SCAN" \
    --arg FileVault_Status "$FILEVAULT_STATUS" \
    --arg FileVault_UserToken "$SECURE_TOKEN_STATUS" \
    --arg FileVault_BootToken "$BOOTSTRAP_TOKEN_STATUS" \
    --arg BuildDate "$BuildDate" \
    --arg LastBootTime "$LastBootTime" \
    --arg MAC0 "$MAC0" \
    --arg MAC1 "$MAC1" \
    --arg MAC2 "$MAC2" \
    --arg MAC3 "$MAC3" \
    --arg MAC4 "$MAC4" \
    '
    {
        ManagedDeviceName: $ManagedDeviceName,
        ManagedDeviceID: $ManagedDeviceID,
        DefenderState: "",
        DefenderStart: "",
        DefSpySigAge: "",
        DefNisSigAge: "",
        DefAVSigAge: "",
        DefAMEngine: "",
        BitlockerState: "",
        BitlockerStart: "",
        BitEncrypted: "",
        BitEncryption: "",
        BitProtected: "",
        BitProtector: "",
        XProtect_Version: $XProtect_Version,
        XProtect_Meta: $XProtect_Meta,
        XProtect_Launch: $XProtect_Launch,
        XProtect_Background: $XProtect_Background,
        FileVault_Status: $FileVault_Status,
        FileVault_UserToken: $FileVault_UserToken,
        FileVault_BootToken: $FileVault_BootToken,
        BuildDate: $BuildDate,
        LastBootTime: $LastBootTime,
        MAC0: $MAC0,
        MAC1: $MAC1,
        MAC2: $MAC2,
        MAC3: $MAC3,
        MAC4: $MAC4
    }
    '
)
Write_Log "$LogFile" "JSON: $jsonData"
#
#
#
# Debugging
echo "$jsonData"
exit 0
#
#----------------------------
# Send json
#----------------------------
http_code=$(curl -s \
  -o /dev/null \
  -w "%{http_code}" \
  -X POST "$URL" \
  --cert "System.keychain:$IDENTITY_NAME" \
  -H "Content-Type: application/json" \
  --data-binary "[$jsonData]"
)
Write_Log "$LogFile" "Http Code: $http_code"
#
#----------------------------
# Report resulting status
#----------------------------
if [[ "$http_code" == "204" ]]; then
    echo "SUCCESS"
else
    echo "FAILED: HTTP $http_code"
    exit 1
fi
