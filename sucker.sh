#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[1;36m'
YELLOW='\033[1;33m'
MAGENTA='\033[1;35m'
NC='\033[0m'

# Check required tools
tools=(subfinder assetfinder amass jq gau unfurl httpx-toolkit katana curl)
for tool in "${tools[@]}"; do
  if ! command -v "$tool" &> /dev/null; then
    echo -e "${RED}[-] Required tool not found: $tool${NC}"
    exit 1
  fi
done

# Ask for domain input
read -p "Enter the domain (e.g. example.com): " domain
if [[ -z "$domain" ]]; then
    echo -e "${RED}[-] No domain provided. Exiting.${NC}"
    exit 1
fi

# Setup directories
mkdir -p "recon/$domain/js_dump"
cd "recon/$domain" || exit 1

echo -e "${CYAN}[*] Starting Subdomain Enumeration for: $domain${NC}"

# Run subdomain tools
subfinder -d "$domain" -silent > subfinder.txt
assetfinder --subs-only "$domain" > assetfinder.txt
amass enum -passive -d "$domain" > amass.txt
curl -s "https://crt.sh/?q=%25.${domain}&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > crtsh.txt
echo "$domain" | gau --subs | unfurl --unique domains > gau.txt
echo "$domain" | waybackurls | unfurl --unique domains > waybackurls.txt

# Combine all into mainsubdomain.txt
echo -e "${CYAN}[*] Combining subdomain results...${NC}"
cat subfinder.txt assetfinder.txt amass.txt crtsh.txt gau.txt waybackurls.txt | sort -u > mainsubdomain.txt
echo -e "${GREEN}[+] Total Unique Subdomains: $(wc -l < mainsubdomain.txt)${NC}"

# Probe with httpx-toolkit
echo -e "${CYAN}[*] Probing for alive subdomains...${NC}"
cat mainsubdomain.txt | httpx-toolkit -ports 80,443,8080,8000,8888 -threads 50 -silent > subdomain_alive.txt
echo -e "${GREEN}[+] Live Subdomains: $(wc -l < subdomain_alive.txt)${NC}"

# Crawl with katana
echo -e "${CYAN}[*] Crawling alive subdomains with katana...${NC}"
katana -list subdomain_alive.txt -depth 5 -silent -o endpoints.txt

# Extract JS files
echo -e "${CYAN}[*] Extracting .js files...${NC}"
grep -E "\.js(\?|$)" endpoints.txt | sort -u > js.txt
echo -e "${GREEN}[+] JS Files Collected: $(wc -l < js.txt)${NC}"

# Secret detection setup
> results.json

declare -A regex_patterns=(
  ["Google_API"]="AIza[0-9A-Za-z\\-_]{35}"
  ["Firebase"]="AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}"
  ["Mailgun"]="key-[0-9a-zA-Z]{32}"
  ["Stripe"]="sk_live_[0-9a-zA-Z]{24}"
  ["AWS_Secret"]="(?i)aws(.{0,20})?(secret|key)[\"'\\s:=]{0,10}[A-Za-z0-9/+=]{40}"
  ["Generic_Token"]="(api[_-]?key|secret|token|auth|bearer|authorization)[\"'\\s:=]{0,10}[\"'A-Za-z0-9_\-]{10,}"
)

echo -e "${CYAN}[*] Scanning JavaScript files for secrets...${NC}"

while read -r url; do
  echo -e "${YELLOW}[*] Downloading: $url${NC}"
  filename=$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g')
  filepath="js_dump/$filename.js"

  curl -s "$url" -o "$filepath"
  if [[ ! -s "$filepath" ]]; then
    echo -e "${RED}[-] Empty or failed file: $url${NC}"
    continue
  fi

  echo -e "${GREEN}[✓] Downloaded: $filename.js${NC}"
  echo -e "${CYAN}[*] Scanning $filename.js...${NC}"
  found_any=false

  for name in "${!regex_patterns[@]}"; do
    regex="${regex_patterns[$name]}"
    matches=$(grep -aoE "$regex" "$filepath")

    if [[ -n "$matches" ]]; then
      found_any=true
      echo -e "${RED}[!] ${MAGENTA}${name}${NC} ${RED}detected in ${filename}.js${NC}"
      echo "$matches" | while read -r key; do
        echo -e "  ${YELLOW}→ ${GREEN}${key}${NC}"
        echo "{\"file\":\"$filename.js\",\"type\":\"$name\",\"key\":\"$key\"}" >> results.json

        # Validate Google API Key
        if [[ $name == "Google_API" ]]; then
          status=$(curl -s "https://maps.googleapis.com/maps/api/geocode/json?address=New+York&key=$key" | grep -o '"error_message"\|"OK"' | head -1)
          echo -e "     ${CYAN}[Validation]${NC} → $status"
        fi
      done
    fi
  done

  [[ $found_any == false ]] && echo -e "${GREEN}[✓] No secrets found in $filename.js${NC}"
  echo ""
done < js.txt

echo -e "${MAGENTA}[✓] Recon complete. Secrets saved in results.json${NC}"
