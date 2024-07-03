#!/bin/bash

# ANSI color escape sequences
RED='\033[1;31m'
GREEN='\033[1;32m'
NC='\033[0m' # No Color

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check for dependencies
check_dependencies() {
    local dependencies=(curl amass assetfinder httpx nmap gobuster sslscan whatweb wpscan wafw00f nikto)
    for cmd in "${dependencies[@]}"; do
        if ! command_exists "$cmd"; then
            echo -e "${RED}Error: $cmd is not installed.${NC}"
            exit 1
        fi
    done
}

# Function to prompt user for URL and check if it requires authentication
prompt_for_url() {
    read -p "Enter the website URL: " url
    # Extract domain from the URL
    domain=$(echo "$url" | awk -F/ '{print $3}')
    domain=${domain:-$url}
    response=$(curl -s -o /dev/null -w "%{http_code}" "$url")
    if [ "$response" == "401" ]; then
        echo -e "${RED}Authentication required.${NC}"
        read -p "Enter username: " username
        read -s -p "Enter password: " password
        echo ""
    else
        username=""
        password=""
    fi
}

# Function to show the main menu
show_menu() {
    echo -e "\n\033[1;34m=== Web Enumeration Script ===\033[0m"
    echo -e "\033[1;33m1. \033[0mEnumerate Web Server"
    echo -e "\033[1;33m2. \033[0mEnumerate HTTP Security Headers"
    echo -e "\033[1;33m3. \033[0mEnumerate Subdomains"
    echo -e "\033[1;33m4. \033[0mEnumerate Cookies"
    echo -e "\033[1;33m5. \033[0mEnumerate Open Ports"
    echo -e "\033[1;33m6. \033[0mEnumerate Website Endpoints"
    echo -e "\033[1;33m7. \033[0mCheck SSL/TLS Configuration"
    echo -e "\033[1;33m8. \033[0mEnumerate Technologies"
    echo -e "\033[1;33m9. \033[0mCheck for CMS"
    echo -e "\033[1;33m10. \033[0mCheck for Web Application Firewall"
    echo -e "\033[1;33m11. \033[0mPerform Full Vulnerability Scan"
    echo -e "\033[1;33m12. \033[0mExit"
    read -p "Please choose an option (\033[1;32m1-12\033[0m): " choice
    handle_choice "$choice"
}

# Function to handle the user's choice
handle_choice() {
    local choice=$1
    case $choice in
        1) enumerate_web_server ;;
        2) enumerate_http_headers ;;
        3) enumerate_subdomains ;;
        4) enumerate_cookies ;;
        5) enumerate_open_ports ;;
        6) enumerate_website_endpoints ;;
        7) check_ssl_configuration ;;
        8) enumerate_technologies ;;
        9) check_cms ;;
        10) check_waf ;;
        11) perform_vulnerability_scan ;;
        12) echo "Exiting."; exit 0 ;;
        *) echo -e "${RED}Invalid option. Please try again.${NC}"; show_menu ;;
    esac
}

# Function to go back to the main menu
go_back() {
    read -p "Press [Enter] to return to the main menu..."
    show_menu
}

# Functions for each menu option

enumerate_web_server() {
    local server_info=$(curl -sI "$url" -u "$username:$password" | grep -i "Server")
    if [ -z "$server_info" ]; then
        echo "No server information found."
    else
        echo "Server Information: $server_info"
    fi
    go_back
}

enumerate_http_headers() {
    local headers=$(curl -sI "$url" -u "$username:$password" 2>/dev/null)

    if [ -z "$headers" ]; then
        echo "Failed to retrieve headers from $url. Check URL and try again."
        go_back
        return
    fi

    echo -e "HTTP Security Headers:"
    check_header() {
        local header="$1"
        if echo "$headers" | grep -qi "$header"; then
            echo -e "${GREEN}Present: $header${NC}"
        else
            echo -e "${RED}Missing: $header${NC}"
        fi
    }

    check_header "Strict-Transport-Security"
    check_header "Content-Security-Policy"
    check_header "X-Content-Type-Options"
    check_header "X-Frame-Options"
    check_header "X-XSS-Protection"

    go_back
}

enumerate_subdomains() {
    read -p "Enter the domain: " domain
    echo "Enumerating subdomains with amass..."
    amass enum -d "$domain" -o amass_subdomains.txt
    echo "Enumerating subdomains with assetfinder..."
    assetfinder --subs-only "$domain" > assetfinder_subdomains.txt
   
    # Combine and deduplicate subdomains
    cat amass_subdomains.txt assetfinder_subdomains.txt | sort -u > all_subdomains.txt

    echo "Checking live subdomains..."
    cat all_subdomains.txt | httpx -silent -status-code | grep "\[200\]" | cut -d " " -f 1 > live_subdomains.txt
    echo "Live Subdomains:"
    while read -r subdomain; do
        echo -e "${GREEN}$subdomain${NC}"
    done < live_subdomains.txt

    # Clean up
    rm amass_subdomains.txt assetfinder_subdomains.txt all_subdomains.txt live_subdomains.txt
    go_back
}

enumerate_cookies() {
    local cookies=$(curl -sI "$url" -u "$username:$password" | grep -i "Set-Cookie")
    echo "Cookies:"
    if [ -z "$cookies" ]; then
        echo "No cookies found."
    else
        echo "$cookies" | while read -r line; do
            echo "$line"
            [[ "$line" != *"HttpOnly"* ]] && echo -e "${RED}Missing: HttpOnly${NC}"
            [[ "$line" != *"Secure"* ]] && echo -e "${RED}Missing: Secure${NC}"
            [[ "$line" != *"SameSite"* ]] && echo -e "${RED}Missing: SameSite${NC}"
        done
    fi
    go_back
}

enumerate_open_ports() {
    read -p "Enter the domain or IP: " target
    echo "Enumerating open ports..."
    nmap -sV "$target"
    go_back
}

enumerate_website_endpoints() {
    read -p "Enter the wordlist path: " wordlist
    echo "Enumerating website endpoints..."
    gobuster dir -u "$url" -w "$wordlist" -o gobuster_results.txt -u "$username:$password"
    cat gobuster_results.txt
    rm gobuster_results.txt
    go_back
}

check_ssl_configuration() {
    echo "Checking SSL/TLS configuration..."
    /opt/testssl.sh/testssl.sh "$domain" > testssl_results.txt
    cat testssl_results.txt
    rm testssl_results.txt
    go_back
}

enumerate_technologies() {
    echo "Enumerating technologies..."
    whatweb "$url" -u "$username:$password" > whatweb_results.txt
    cat whatweb_results.txt
    rm whatweb_results.txt
    go_back
}

check_cms() {
    echo "Checking for CMS (WordPress)..."
    wpscan --url "$url" --enumerate p,t,u --user "$username" --password "$password" > wpscan_results.txt
    cat wpscan_results.txt
    rm wpscan_results.txt
    go_back
}

check_waf() {
    echo "Checking for Web Application Firewall..."
    wafw00f "$url" -u "$username:$password"
    go_back
}

perform_vulnerability_scan() {
    echo "Performing full vulnerability scan with Nikto..."
    nikto -h "$url" -id "$username:$password"
    go_back
}

# Main script execution
check_dependencies
prompt_for_url

# Main loop to display menu repeatedly
while true; do
    show_menu
done

