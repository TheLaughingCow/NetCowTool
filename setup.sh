#!/bin/bash

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${YELLOW}Importing Kali GPG archive key...${NC}"
sudo curl -fsSL https://archive.kali.org/archive-key.asc | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/kali-archive.gpg > /dev/null

echo -e "${YELLOW}Updating package lists...${NC}"
sudo apt-get clean
sudo apt-get update --fix-missing
echo -e "${GREEN}Update completed.${NC}"

echo -e "${YELLOW}Checking for curl...${NC}"
if ! command -v curl &> /dev/null; then
    echo -e "${YELLOW}Installing curl...${NC}"
    sudo apt-get install -y curl
    echo -e "${GREEN}curl installed.${NC}"
else
    echo -e "${GREEN}curl is already installed.${NC}"
fi

echo -e "${YELLOW}Installing libsystemd-dev (latest available)...${NC}"
if ! dpkg -s libsystemd-dev &> /dev/null; then
    VERSION=$(apt-cache policy libsystemd-dev | grep Candidate | awk '{print $2}')
    sudo apt-get install -y libsystemd-dev=$VERSION
else
    echo -e "${GREEN}libsystemd-dev already installed.${NC}"
fi

echo -e "${YELLOW}Installing dependencies for discovery...${NC}"
sudo apt-get install -y gcc lldpd network-manager

echo -e "${YELLOW}(Re)Installing libpcap-dev...${NC}"
sudo apt-get install --reinstall -y libpcap-dev

echo -e "${YELLOW}Checking if pcap.h is present...${NC}"
if [[ ! -f /usr/include/pcap/pcap.h ]]; then
    echo -e "${RED}pcap.h missing. libpcap-dev may not be properly installed.${NC}"
    exit 1
fi

sudo systemctl start lldpd
sudo systemctl enable lldpd
echo -e "${GREEN}Dependencies for discovery installed.${NC}"

echo -e "${YELLOW}Installing dependencies for ssid...${NC}"
sudo apt-get install -y libiw-dev
echo -e "${GREEN}Dependencies for ssid installed.${NC}"

echo -e "${YELLOW}Installing dependencies for scanner...${NC}"
sudo apt-get install -y libjson-c-dev macchanger libxml2-dev

echo -e "${YELLOW}Checking for nmap...${NC}"
if ! command -v nmap &> /dev/null; then
    echo -e "${YELLOW}Installing nmap...${NC}"
    sudo apt-get install -y nmap
    echo -e "${GREEN}nmap installed.${NC}"
else
    echo -e "${GREEN}nmap is already installed.${NC}"
fi

echo -e "${GREEN}Dependencies for scanner installed.${NC}"

echo -e "${YELLOW}Checking if pip is installed...${NC}"
if ! command -v pip3 &> /dev/null; then
    echo -e "${YELLOW}Installing pip...${NC}"
    sudo apt-get install -y python3-pip
    echo -e "${GREEN}pip installed.${NC}"
else
    echo -e "${GREEN}pip is already installed. Skipping update.${NC}"
fi

echo -e "${YELLOW}Checking if simple-term-menu is installed...${NC}"
export PYTHONPATH=/usr/local/lib/python3.11/dist-packages:$PYTHONPATH
if ! grep -q "export PYTHONPATH=/usr/local/lib/python3.11/dist-packages:\$PYTHONPATH" ~/.bashrc; then
    echo "export PYTHONPATH=/usr/local/lib/python3.11/dist-packages:\$PYTHONPATH" >> ~/.bashrc
    source ~/.bashrc
fi

if python3 -c "import simple_term_menu" &> /dev/null; then
    echo -e "${GREEN}simple-term-menu is already installed.${NC}"
else
    echo -e "${YELLOW}Installing simple-term-menu...${NC}"
    sudo -E python3 -m pip install --force-reinstall --break-system-packages simple-term-menu
    echo -e "${GREEN}simple-term-menu installed.${NC}"
fi

echo -e "${YELLOW}Compiling programs...${NC}"
gcc "$SCRIPT_DIR/discovery.c" -o "$SCRIPT_DIR/discovery" -lpcap
gcc "$SCRIPT_DIR/ssid.c" -o "$SCRIPT_DIR/ssid" -liw
gcc "$SCRIPT_DIR/scanner.c" -o "$SCRIPT_DIR/scanner" -ljson-c $(xml2-config --cflags --libs)

if [[ -f "$SCRIPT_DIR/ssid" && -f "$SCRIPT_DIR/scanner" ]]; then
    echo -e "${GREEN}The ssid and scanner programs were successfully compiled.${NC}"
else
    echo -e "${RED}Error compiling the ssid and scanner programs.${NC}"
    exit 1
fi

echo -e "${GREEN}Script completed. Your system is ready.${NC}"
