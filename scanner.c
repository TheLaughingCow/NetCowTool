#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#define GREEN   "\x1b[32m"
#define YELLOW  "\x1b[33m"
#define RED     "\x1b[31m"
#define COLOR_RESET   "\x1b[0m"
#define MAX_IP_LENGTH 16
#define MAX_IPS 254
#define COMMAND_SIZE 4096
#define INITIAL_BUFFER_SIZE 52000

char interface[50];

void restartNetworkManager(void);
void get_network_interface_name(char *interface_name);
void changeMACAddressAndRenewIP(char *interface);
char* getLocalNetworkAddress(char *jsonFilePath);
void scanActiveHostsAndUpdateJSON(char *network, char *jsonFilePath, int vlan_id, const char *vlanFilePath);
void setVLAN(char *interface, int vlan_id);
void waitForDHCP(char *vlan_interface);
char* updateNetworkAddressForVLAN(char *vlan_interface, char *jsonFilePath, int vlan_id, int netmask_bits);
void resetNetworkInterface(char *interface);
void processVLANs(char *interface, char *jsonFilePath);
void mergeAndDeleteJSONFiles(const char *filePath1, const char *filePath2, const char *mergedFilePath);
void appendToBuffer(char **buffer, const char *data, size_t *bufferSize);
void scanAllHostsAndSaveToXML(struct json_object *activeHosts);
void readXMLAndSaveToJson(const char *xmlFilePath, const char *jsonFilePath);
int MyStrcasestr(const char *haystack, const char *needle);
void readIPsFromJSON(const char *jsonFilePath, char **ipList, int *ipCount);
int getTTL(const char *ip);
void categorizeHost(const char *os_name, const char *vendor, json_object *host_json, int *hasFirewalls, int *hasServers, int *hasSwitchWifi, int *hasTelephonie, int *hasPoste, int *hasImprimantes, int *hasOthers, char *firewalls, char *servers, char *switchWifi, char *telephonie, char *poste, char *imprimantes, char *others, const char *hostDetails);
void createHtml(json_object *jsonRoot, const char *htmlFilePath, int isVLAN, int vlan_id);
void scanAndClassifyVLANHosts(struct json_object *parsed_json, const char *htmlFilePath);
void signalHandler(int signum);
void cleanup(void);
char* str_replace(char *str, const char *old, const char *new);
void scanNearbyNetworks(char *jsonFilePath);

void get_network_interface_name(char *interface_name) {
    FILE *fp = fopen("/proc/net/route", "r");
    if (fp == NULL) {
        perror(RED"Error opening /proc/net/route"COLOR_RESET);
        strcpy(interface_name, "unknown");
        return;
    }
    
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        char ifname[16];
        unsigned long dest;
        
        if (sscanf(line, "%s\t%lX", ifname, &dest) == 2) {
            if (dest == 0) {
                strcpy(interface_name, ifname);
                fclose(fp);
                return;
            }
        }
    }
    
    fclose(fp);
    strcpy(interface_name, "unknown");
}

void changeMACAddressAndRenewIP(char *interface) {
    int status;
    char command[256];

    printf(YELLOW"[*] Shutting down NetworkManager...\n" COLOR_RESET);
    status = system("systemctl stop NetworkManager");
    if (status != 0) {
        printf(RED"[✗] NetworkManager shutdown error\n" COLOR_RESET);
        return;
    }

    printf(YELLOW"[*] Changing the MAC address...\n" COLOR_RESET);
    sprintf(command, "macchanger -r %s > /dev/null", interface);
    status = system(command);
    if (status != 0) {
        printf(RED"[✗] Error when changing MAC address\n" COLOR_RESET);
        return;
    }

    printf(YELLOW"[*] IP address renewal...\n" COLOR_RESET);
    sprintf(command, "dhclient %s", interface);
    status = system(command);
    if (status != 0) {
        printf(RED"[✗] Error when renewing DHCP lease\n" COLOR_RESET);
        return;
    }

    printf(YELLOW"[*] Restarting NetworkManager...\n" COLOR_RESET);
    status = system("systemctl restart NetworkManager");
    if (status != 0) {
        printf(RED"[✗] Error restarting NetworkManager\n" COLOR_RESET);
        return;
    }

    printf(GREEN"[✓] Network configuration successfully updated\n" COLOR_RESET);
}

char* getLocalNetworkAddress(char *jsonFilePath) {
    FILE *file = fopen(jsonFilePath, "r");
    if (file == NULL) {
        fprintf(stderr, RED "Error : no '%s' file. " COLOR_RESET "Please run Discovery first\n", jsonFilePath);
        exit(EXIT_FAILURE);
    }

    struct json_object *parsed_json, *defaultNetwork, *localNetworkAddress;

    parsed_json = json_object_from_file(jsonFilePath);
    json_object_object_get_ex(parsed_json, "DefaultNetwork", &defaultNetwork);
    json_object_object_get_ex(defaultNetwork, "LocalNetworkAddress", &localNetworkAddress);

    char *networkAddress = strdup(json_object_get_string(localNetworkAddress));

    json_object_put(parsed_json);
    fclose(file);

    return networkAddress;
}

void scanActiveHostsAndUpdateJSON(char *network, char *jsonFilePath, int vlan_id, const char *vlanFilePath) {
    FILE *fp;
    char command[256];
    char line[1035];
    struct json_object *parsed_json, *vlans, *vlan, *activeHostsArray, *targetNetworkObject;
    char network_with_mask[256];

    if (vlan_id == -1) {
        snprintf(network_with_mask, sizeof(network_with_mask), "%s/24", network);
    } else {
        strncpy(network_with_mask, network, sizeof(network_with_mask) - 1);
        network_with_mask[sizeof(network_with_mask) - 1] = '\0';
    }

    sprintf(command, "nmap -sn -T4 --min-parallelism 100 --max-parallelism 256 --min-hostgroup 64 --max-hostgroup 256 --min-rtt-timeout 100ms --max-rtt-timeout 200ms --initial-rtt-timeout 100ms --max-retries 1 %s | grep 'Nmap scan report for' | awk '{print $NF}' | sed 's/[()]//g'", network_with_mask);
    printf(YELLOW"...Scan Nmap en cours reseau: " COLOR_RESET "%s"YELLOW " ...\n" COLOR_RESET, network_with_mask);

    if (vlan_id == -1) {
        parsed_json = json_object_from_file(jsonFilePath);
        if (!parsed_json) {
            parsed_json = json_object_new_object();
            json_object_object_add(parsed_json, "DefaultNetwork", json_object_new_object());
        }
        json_object_object_get_ex(parsed_json, "DefaultNetwork", &targetNetworkObject);
    } else if (vlan_id == -2) {

        parsed_json = json_object_from_file(jsonFilePath);
        if (!parsed_json) {
            parsed_json = json_object_new_object();
            json_object_object_add(parsed_json, "NearbyNetworks", json_object_new_array());
        }
        
        struct json_object *nearbyNetworks;
        json_object_object_get_ex(parsed_json, "NearbyNetworks", &nearbyNetworks);
        
        targetNetworkObject = NULL;
        size_t n_networks = json_object_array_length(nearbyNetworks);
        for (size_t i = 0; i < n_networks; i++) {
            struct json_object *network_obj = json_object_array_get_idx(nearbyNetworks, i);
            struct json_object *address;
            const char *addr;
            
            if (json_object_object_get_ex(network_obj, "NearbyNetworkAddress", &address)) {
                addr = json_object_get_string(address);
            } else if (json_object_object_get_ex(network_obj, "Network", &address)) {
                addr = json_object_get_string(address);
            } else {
                continue;
            }
            
            if (strcmp(addr, network) == 0) {
                targetNetworkObject = network_obj;
                break;
            }
        }

        if (!targetNetworkObject) {
            targetNetworkObject = json_object_new_object();
            json_object_object_add(targetNetworkObject, "Network", json_object_new_string(network));
            json_object_object_add(targetNetworkObject, "Type", json_object_new_string("Unknown"));
            json_object_array_add(nearbyNetworks, targetNetworkObject);
        }
    } else {
        parsed_json = json_object_from_file(vlanFilePath);
        if (!parsed_json) {
            parsed_json = json_object_new_object();
            json_object_object_add(parsed_json, "VLANs", json_object_new_array());
        }
        json_object_object_get_ex(parsed_json, "VLANs", &vlans);
        
        targetNetworkObject = NULL;
        size_t vlan_count = json_object_array_length(vlans);
        for (size_t i = 0; i < vlan_count; i++) {
            vlan = json_object_array_get_idx(vlans, i);
            struct json_object *id;
            json_object_object_get_ex(vlan, "ID", &id);
            if (json_object_get_int(id) == vlan_id) {
                targetNetworkObject = vlan;
                break;
            }
        }
        if (!targetNetworkObject) {
            targetNetworkObject = json_object_new_object();
            json_object_object_add(targetNetworkObject, "ID", json_object_new_int(vlan_id));
            json_object_array_add(vlans, targetNetworkObject);
        }
    }

    json_object_object_get_ex(targetNetworkObject, "ActiveHosts", &activeHostsArray);
    if (activeHostsArray == NULL) {
        activeHostsArray = json_object_new_array();
        json_object_object_add(targetNetworkObject, "ActiveHosts", activeHostsArray);
    }

    struct json_object *newHostsArray = json_object_new_array();

    fp = popen(command, "r");
    if (fp == NULL) {
        perror("Error running nmap");
        json_object_put(parsed_json);
        json_object_put(newHostsArray);
        return;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        line[strcspn(line, "\n")] = 0;
        json_object_array_add(newHostsArray, json_object_new_string(line));
    }

    pclose(fp);

    size_t n_new_hosts = json_object_array_length(newHostsArray);
    for (size_t i = 0; i < n_new_hosts; i++) {
        const char *new_ip = json_object_get_string(json_object_array_get_idx(newHostsArray, i));
        int ip_exists = 0;

        size_t n_existing_hosts = json_object_array_length(activeHostsArray);
        for (size_t j = 0; j < n_existing_hosts; j++) {
            const char *existing_ip = json_object_get_string(json_object_array_get_idx(activeHostsArray, j));
            if (strcmp(new_ip, existing_ip) == 0) {
                ip_exists = 1;
                break;
            }
        }

        if (!ip_exists) {
            json_object_array_add(activeHostsArray, json_object_new_string(new_ip));
        }
    }

    json_object_to_file((vlan_id == -1 || vlan_id == -2) ? jsonFilePath : vlanFilePath, parsed_json);

    json_object_put(parsed_json);
    json_object_put(newHostsArray);

    printf(GREEN"[✓] Scan completed for " COLOR_RESET "%s\n", network_with_mask);
}

void setVLAN(char *interface, int vlan_id) {
    char command[256];
    char vlan_interface[16];

    sprintf(vlan_interface, "vlan%d", vlan_id);

    printf(YELLOW"[*] Configuring the VLAN interface %d...\n" COLOR_RESET, vlan_id);

    sprintf(command, "ip link delete %s 2>/dev/null", vlan_interface);
    system(command);

    sprintf(command, "ip link add link %s name %s type vlan id %d", interface, vlan_interface, vlan_id);
    if (system(command) != 0) {
        printf(RED"[✗] Error creating VLAN interface %d\n" COLOR_RESET, vlan_id);
        return;
    }

    sprintf(command, "ip link set dev %s up", vlan_interface);
    if (system(command) != 0) {
        printf(RED"[✗] Error activating VLAN interface %d\n" COLOR_RESET, vlan_id);
        return;
    }

    printf(GREEN"[✓] VLAN %d interface successfully configured\n" COLOR_RESET, vlan_id);
}

void waitForDHCP(char *vlan_interface) {
    char command[256];
    
    sprintf(command, "dhclient %s", vlan_interface);
    system(command);

    sleep(2);

}

char* updateNetworkAddressForVLAN(char *vlan_interface, char *jsonFilePath, int vlan_id, int netmask_bits) {
    char command[256];
    char line[256];
    FILE *fp;
    struct in_addr ipaddr;
    char networkAddress[INET_ADDRSTRLEN];
    char networkAddressWithMask[INET_ADDRSTRLEN];

    sprintf(command, "ip addr show %s | grep 'inet '", vlan_interface);
    fp = popen(command, "r");
    if (fp == NULL) {
        perror("[✗] Error during command execution");
        return NULL;
    }

    if (fgets(line, sizeof(line), fp) != NULL) {
        char addr_str[INET_ADDRSTRLEN];
        sscanf(line, " inet %[^/]/%d", addr_str, &netmask_bits);
        inet_pton(AF_INET, addr_str, &ipaddr);

        uint32_t mask = htonl(0xFFFFFFFF << (32 - netmask_bits));
        ipaddr.s_addr &= mask;
        inet_ntop(AF_INET, &ipaddr, networkAddress, INET_ADDRSTRLEN);
        sprintf(networkAddressWithMask, "%s/%d", networkAddress, netmask_bits);
    }
    pclose(fp);

    struct json_object *parsed_json, *vlans, *vlan;
    int vlan_found = 0;

    parsed_json = json_object_from_file(jsonFilePath);
    if (!json_object_object_get_ex(parsed_json, "VLANs", &vlans)) {
        vlans = json_object_new_array();
        json_object_object_add(parsed_json, "VLANs", vlans);
    }

    int vlan_count = json_object_array_length(vlans);
    for (int i = 0; i < vlan_count; i++) {
        vlan = json_object_array_get_idx(vlans, i);
        struct json_object *id;
        json_object_object_get_ex(vlan, "ID", &id);
        if (json_object_get_int(id) == vlan_id) {
            json_object_object_add(vlan, "VLANNetworkAddress", json_object_new_string(networkAddressWithMask));
            vlan_found = 1;
            break;
        }
    }

    if (!vlan_found) {
        vlan = json_object_new_object();
        json_object_object_add(vlan, "ID", json_object_new_int(vlan_id));
        json_object_object_add(vlan, "VLANNetworkAddress", json_object_new_string(networkAddressWithMask));
        json_object_array_add(vlans, vlan);
    }

    json_object_to_file(jsonFilePath, parsed_json);
    json_object_put(parsed_json);

    return strdup(networkAddressWithMask);
}

void resetNetworkInterface(char *interface) {
    char command[256];

    printf("Restore original MAC address...\n");
    sprintf(command, "macchanger -p %s > /dev/null", interface);
    system(command);

    sprintf(command, "ip link set %s down", interface);
    system(command);
    
    sleep(1);
    
    sprintf(command, "ip addr flush dev %s", interface);
    system(command);
    
    sprintf(command, "ip link set %s up", interface);
    system(command);
    
    sleep(1);

    sprintf(command, "dhclient -r %s", interface);
    system(command);
    sleep(1);
    sprintf(command, "dhclient %s", interface);
    system(command);

    restartNetworkManager();

    printf("Interface %s reset\n", interface);
}

void processVLANs(char *interface, char *jsonFilePath) {
    struct json_object *parsed_json, *vlans;
    int vlan_count;
    char *vlanJsonFilePath = "./network_info_vlan.json";

    parsed_json = json_object_from_file(jsonFilePath);
    if (parsed_json == NULL) {
        fprintf(stderr, "[✗] Error loading the main JSON file.\n");
        return;
    }

    if (!json_object_object_get_ex(parsed_json, "VLANs", &vlans)) {
        fprintf(stderr, "[✗] No VLANs object found in the JSON file.\n");
        json_object_put(parsed_json);
        return;
    }

    vlan_count = json_object_array_length(vlans);
    if (vlan_count == 0) {
        fprintf(stderr, "The VLAN table is empty.\n");
        json_object_put(parsed_json);
        return;
    }

    for (int i = 0; i < vlan_count; i++) {
        struct json_object *vlan = json_object_array_get_idx(vlans, i);
        struct json_object *id;
        if (json_object_object_get_ex(vlan, "ID", &id)) {
            int vlan_id = json_object_get_int(id);
            char vlan_interface[256];
            sprintf(vlan_interface, "vlan%d", vlan_id);

            setVLAN(interface, vlan_id);
            waitForDHCP(vlan_interface);
            char *vlan_network = updateNetworkAddressForVLAN(vlan_interface, jsonFilePath, vlan_id, 24);

            if (vlan_network) {
                scanActiveHostsAndUpdateJSON(vlan_network, jsonFilePath, vlan_id, vlanJsonFilePath);
                free(vlan_network);
            }
        }
    }

    json_object_put(parsed_json);
}

void mergeAndDeleteJSONFiles(const char *filePath1, const char *filePath2, const char *mergedFilePath) {
    struct json_object *json1 = NULL, *json2 = NULL, *merged_json, *json1_vlans, *json2_vlans, *vlan;
    struct json_object *defaultNetwork1, *defaultNetwork2, *activeHosts1, *activeHosts2;
    int i, j;

    json1 = json_object_from_file(filePath1);
    json2 = json_object_from_file(filePath2);

    if (json1 && json_object_object_get_ex(json1, "DefaultNetwork", &defaultNetwork1)) {

        if (!json_object_object_get_ex(defaultNetwork1, "ActiveHosts", &activeHosts1)) {
            activeHosts1 = json_object_new_array();
            json_object_object_add(defaultNetwork1, "ActiveHosts", activeHosts1);
        }

        if (json2 && json_object_object_get_ex(json2, "DefaultNetwork", &defaultNetwork2) &&
            json_object_object_get_ex(defaultNetwork2, "ActiveHosts", &activeHosts2)) {
            
            size_t n_hosts = json_object_array_length(activeHosts2);
            for (size_t i = 0; i < n_hosts; i++) {
                const char *new_ip = json_object_get_string(json_object_array_get_idx(activeHosts2, i));
                int exists = 0;

                size_t existing_count = json_object_array_length(activeHosts1);
                for (size_t j = 0; j < existing_count; j++) {
                    const char *existing_ip = json_object_get_string(json_object_array_get_idx(activeHosts1, j));
                    if (strcmp(existing_ip, new_ip) == 0) {
                        exists = 1;
                        break;
                    }
                }

                if (!exists) {
                    json_object_array_add(activeHosts1, json_object_get(json_object_array_get_idx(activeHosts2, i)));
                }
            }
        }
    }

    if (!json1 || !json_object_object_get_ex(json1, "VLANs", &json1_vlans)) {
        json1_vlans = json_object_new_array();
        if (json1) {
            json_object_object_add(json1, "VLANs", json1_vlans);
        }
    }

    if (json2 && json_object_object_get_ex(json2, "VLANs", &json2_vlans)) {
        for (i = 0; i < json_object_array_length(json2_vlans); i++) {
            struct json_object *json2_vlan = json_object_array_get_idx(json2_vlans, i);
            int id2 = json_object_get_int(json_object_object_get(json2_vlan, "ID"));

            int found = 0;
            for (j = 0; j < json_object_array_length(json1_vlans) && !found; j++) {
                vlan = json_object_array_get_idx(json1_vlans, j);
                int id1 = json_object_get_int(json_object_object_get(vlan, "ID"));

                if (id1 == id2) {
                    json_object_object_add(vlan, "ActiveHosts", json_object_object_get(json2_vlan, "ActiveHosts"));
                    found = 1;
                }
            }
        }
    }

    merged_json = json1 ? json1 : json_object_new_object();

    if (json_object_to_file(mergedFilePath, merged_json) != 0) {
        printf(RED"[✗] Error writing merged JSON file\n" COLOR_RESET);
    } else {
        printf(GREEN"[✓] JSON report successfully generated : %s\n" COLOR_RESET, mergedFilePath);
    }

    json_object_put(merged_json);
    if (json1) remove(filePath1);
    if (json2) remove(filePath2);
}

void appendToBuffer(char **buffer, const char *data, size_t *bufferSize) {
    size_t currentLength = strlen(*buffer);
    size_t dataLength = strlen(data);

    while (currentLength + dataLength >= *bufferSize) {
        *bufferSize *= 2;
        char *temp = realloc(*buffer, *bufferSize);
        if (!temp) {

            fprintf(stderr, RED"[✗] Memory reallocation error\n"COLOR_RESET);
            exit(1);
        }
        *buffer = temp;
    }

    strcat(*buffer, data);
}

void scanAllHostsAndSaveToXML(struct json_object *activeHosts) {
    char ipList[MAX_IPS * MAX_IP_LENGTH + 1] = "";
    size_t n_hosts = json_object_array_length(activeHosts);

    if (n_hosts > MAX_IPS) {
        printf(RED"[✗] Too many hosts for a /24 scan. Limited to 254 hosts.\n"COLOR_RESET);
        n_hosts = MAX_IPS;
    }

    for (size_t i = 0; i < n_hosts; i++) {
        const char* ip = json_object_get_string(json_object_array_get_idx(activeHosts, i));
        size_t space_left = sizeof(ipList) - strlen(ipList) - 1;
        strncat(ipList, ip, space_left);
        if (i < n_hosts - 1) {
            strncat(ipList, " ", space_left - strlen(ip));
        }
    }

    printf(YELLOW"[+] Starting scan OS & PORTS \n"COLOR_RESET);
    char command[COMMAND_SIZE];
    // Optimisation du scan détaillé avec des paramètres de performance
    snprintf(command, sizeof(command), 
        "nmap -sS -sV -O -F -T4 --min-parallelism 100 --max-parallelism 256 --min-hostgroup 64 --max-hostgroup 256 --min-rtt-timeout 100ms --max-rtt-timeout 200ms --initial-rtt-timeout 100ms --max-retries 1 --version-intensity 5 --script=banner %s -oX ./nmap.xml > /dev/null 2>&1", 
        ipList);

    if (system(command) != 0) {
        printf(RED "[✗] Error running Nmap\n"COLOR_RESET);
        return;
    }

    printf(GREEN"[✓] Scan complete\n"COLOR_RESET);
}

void readXMLAndSaveToJson(const char *xmlFilePath, const char *jsonFilePath) {
    xmlDoc *doc = xmlReadFile(xmlFilePath, NULL, 0);
    if (doc == NULL) {
        return;
    }

    xmlNode *root_element = xmlDocGetRootElement(doc);
    struct json_object *jsonRoot = json_object_new_array();

    for (xmlNode *host = root_element->children; host; host = host->next) {
        if (host->type == XML_ELEMENT_NODE && strcmp((const char *)host->name, "host") == 0) {
            struct json_object *jsonHost = json_object_new_object();
            struct json_object *jsonAddress = NULL, *jsonMac = NULL, *jsonVendor = NULL, *jsonOS = NULL, *jsonHostname = NULL;
            struct json_object *jsonPortsArray = json_object_new_array();

            for (xmlNode *child = host->children; child; child = child->next) {
                if (child->type == XML_ELEMENT_NODE) {
                    if (strcmp((const char *)child->name, "address") == 0) {
                        xmlChar *addr = xmlGetProp(child, (const xmlChar *)"addr");
                        xmlChar *type = xmlGetProp(child, (const xmlChar *)"addrtype");

                        if (strcmp((const char *)type, "ipv4") == 0) {
                            jsonAddress = json_object_new_string((const char *)addr);
                        } else if (strcmp((const char *)type, "mac") == 0) {
                            jsonMac = json_object_new_string((const char *)addr);
                            xmlChar *vendor = xmlGetProp(child, (const xmlChar *)"vendor");
                            if (vendor) {
                                jsonVendor = json_object_new_string((const char *)vendor);
                                xmlFree(vendor);
                            }
                        }

                        xmlFree(addr);
                        xmlFree(type);
                    }

                    if (strcmp((const char *)child->name, "ports") == 0) {
                        for (xmlNode *port = child->children; port; port = port->next) {
                            if (port->type == XML_ELEMENT_NODE && strcmp((const char *)port->name, "port") == 0) {
                                xmlChar *portid = xmlGetProp(port, (const xmlChar *)"portid");
                                struct json_object *jsonPort = json_object_new_string((const char *)portid);
                                json_object_array_add(jsonPortsArray, jsonPort);
                                xmlFree(portid);
                            }
                        }
                    }

                    if (strcmp((const char *)child->name, "os") == 0) {
                        int max_accuracy = 0;
                        xmlChar *max_accuracy_name = NULL;

                        for (xmlNode *osmatch = child->children; osmatch; osmatch = osmatch->next) {
                            if (osmatch->type == XML_ELEMENT_NODE && strcmp((const char *)osmatch->name, "osmatch") == 0) {
                                xmlChar *name = xmlGetProp(osmatch, (const xmlChar *)"name");
                                xmlChar *accuracy = xmlGetProp(osmatch, (const xmlChar *)"accuracy");
                                int current_accuracy = atoi((const char *)accuracy);

                                if (current_accuracy > max_accuracy) {
                                    max_accuracy = current_accuracy;
                                    if (max_accuracy_name) {
                                        xmlFree(max_accuracy_name);
                                    }
                                    max_accuracy_name = xmlStrdup(name);
                                }

                                xmlFree(name);
                                xmlFree(accuracy);
                            }
                        }

                        if (max_accuracy_name && max_accuracy >= 95) {
                            char os_name[256];
                            snprintf(os_name, sizeof(os_name), "%s (%d%%)", max_accuracy_name, max_accuracy);
                            jsonOS = json_object_new_string(os_name);
                            xmlFree(max_accuracy_name);
                        } else if (max_accuracy_name) {
                            xmlFree(max_accuracy_name);
                        }
                    }

                    if (strcmp((const char *)child->name, "hostnames") == 0) {
                        jsonHostname = json_object_new_array();
                        for (xmlNode *hostnameNode = child->children; hostnameNode; hostnameNode = hostnameNode->next) {
                            if (hostnameNode->type == XML_ELEMENT_NODE && strcmp((const char *)hostnameNode->name, "hostname") == 0) {
                                xmlChar *name = xmlGetProp(hostnameNode, (const xmlChar *)"name");
                                if (name) {
                                    json_object_array_add(jsonHostname, json_object_new_string((const char *)name));
                                    xmlFree(name);
                                }
                            }
                        }
                    }
                }
            }

            if (jsonAddress != NULL) {
                json_object_object_add(jsonHost, "IP Address", jsonAddress);
            }
            if (jsonMac != NULL) {
                json_object_object_add(jsonHost, "MAC Address", jsonMac);
                if (jsonVendor != NULL) {
                    json_object_object_add(jsonHost, "Vendor", jsonVendor);
                }
            }
            if (jsonPortsArray != NULL) {
                json_object_object_add(jsonHost, "Open Ports", jsonPortsArray);
            }
            if (jsonOS != NULL) {
                json_object_object_add(jsonHost, "OS", jsonOS);
            }
            if (jsonHostname != NULL && json_object_array_length(jsonHostname) > 0) {
                json_object_object_add(jsonHost, "Hostnames", jsonHostname);
            } else if (jsonHostname != NULL) {
                json_object_put(jsonHostname);
            }

            json_object_array_add(jsonRoot, jsonHost);
        }
    }

    FILE *jsonFile = fopen(jsonFilePath, "w");
    if (jsonFile != NULL) {
        const char *jsonString = json_object_to_json_string_ext(jsonRoot, JSON_C_TO_STRING_PRETTY);
        fprintf(jsonFile, "%s", jsonString);
        fclose(jsonFile);
    }

    xmlFreeDoc(doc);
    json_object_put(jsonRoot);

    remove(xmlFilePath);
}


int MyStrcasestr(const char *haystack, const char *needle) {
    if (haystack == NULL || needle == NULL)
        return 0;

    size_t haystack_len = strlen(haystack);
    size_t needle_len = strlen(needle);

    if (haystack_len < needle_len)
        return 0;

    for (size_t i = 0; i <= haystack_len - needle_len; i++) {
        if (strncasecmp(haystack + i, needle, needle_len) == 0)
            return 1;
    }

    return 0;
}

void readIPsFromJSON(const char *jsonFilePath, char **ipList, int *ipCount) {
    struct json_object *parsed_json = json_object_from_file(jsonFilePath);
    if (!parsed_json) {
        fprintf(stderr, RED "[✗] Error : Unable to read JSON file\n" COLOR_RESET);
        return;
    }

    size_t n_hosts = json_object_array_length(parsed_json);
    *ipList = malloc(n_hosts * MAX_IP_LENGTH);
    *ipCount = 0;

    for (size_t i = 0; i < n_hosts; i++) {
        json_object *host = json_object_array_get_idx(parsed_json, i);
        json_object *ip_addr_obj;
        
        if (json_object_object_get_ex(host, "IP Address", &ip_addr_obj)) {
            const char *ip = json_object_get_string(ip_addr_obj);
            strcpy(*ipList + (*ipCount * MAX_IP_LENGTH), ip);
            (*ipCount)++;
        }
    }

    json_object_put(parsed_json);
}

int getTTL(const char *ip) {
    char command[256];
    char output[1024];
    FILE *fp;
    int ttl = -1;

    snprintf(command, sizeof(command), "ping -c 1 %s", ip);
    
    fp = popen(command, "r");
    if (fp == NULL) {
        return -1;
    }

    while (fgets(output, sizeof(output), fp) != NULL) {
        if (strstr(output, "ttl=") != NULL) {
            char *ttl_str = strstr(output, "ttl=");
            if (ttl_str) {
                ttl_str += 4;
                ttl = atoi(ttl_str);
            }
            break;
        }
    }

    pclose(fp);
    return ttl;
}

void categorizeHost(const char *os_name, const char *vendor, json_object *host_json, int *hasFirewalls, int *hasServers, int *hasSwitchWifi, int *hasTelephonie, int *hasPoste, int *hasImprimantes, int *hasOthers, char *firewalls, char *servers, char *switchWifi, char *telephonie, char *poste, char *imprimantes, char *others, const char *hostDetails) {

    json_object *ip_addr_obj;
    const char *ip_addr;
    
    if (json_object_object_get_ex(host_json, "IP Address", &ip_addr_obj)) {
        ip_addr = json_object_get_string(ip_addr_obj);
        int ttl = getTTL(ip_addr);
        
        if (ttl == 128) {
            *hasPoste = 1;
            strcat(poste, hostDetails);
            return;
        }
    }

    if (vendor && (MyStrcasestr(vendor, "Brother") || MyStrcasestr(vendor, "HP") || MyStrcasestr(vendor, "Epson") || MyStrcasestr(vendor, "Canon"))) {
        json_object *ports_obj;
        if (json_object_object_get_ex(host_json, "Open Ports", &ports_obj)) {
            int printer_ports = 0;
            size_t n_ports = json_object_array_length(ports_obj);
            for (size_t i = 0; i < n_ports; i++) {
                json_object *port = json_object_array_get_idx(ports_obj, i);
                const char *port_str = json_object_get_string(port);
                if (strstr(port_str, "515") || strstr(port_str, "631") || strstr(port_str, "9100")) {
                    printer_ports++;
                }
            }
            if (printer_ports >= 2) {
                *hasImprimantes = 1;
                strcat(imprimantes, hostDetails);
                return;
            }
        }
    }

    json_object *ports_obj;
    if (json_object_object_get_ex(host_json, "Open Ports", &ports_obj)) {
        size_t n_ports = json_object_array_length(ports_obj);
        int has_sip_port = 0;
        
        for (size_t i = 0; i < n_ports; i++) {
            json_object *port = json_object_array_get_idx(ports_obj, i);
            const char *port_str = json_object_get_string(port);
            if (strstr(port_str, "5060")) {
                has_sip_port = 1;
                break;
            }
        }
        
        if (has_sip_port && vendor && (MyStrcasestr(vendor, "Yealink") || MyStrcasestr(vendor, "Fanvil"))) {
                *hasTelephonie = 1;
                strcat(telephonie, hostDetails);
                return;
        }
    }

    if ((os_name && MyStrcasestr(os_name, "firewall")) || (vendor && (MyStrcasestr(vendor, "Fortinet") || MyStrcasestr(vendor, "Sagemcom") || MyStrcasestr(vendor, "Sophos")))) {
        *hasFirewalls = 1;
        strcat(firewalls, hostDetails);
        return;
    }

    if ((vendor && MyStrcasestr(vendor, "VMware")) || (os_name && (MyStrcasestr(os_name, "ilo") || MyStrcasestr(os_name, "idrac")))) {
        *hasServers = 1;
        strcat(servers, hostDetails);
        return;
    }

    if ((os_name && MyStrcasestr(os_name, "switch")) || (vendor && (MyStrcasestr(vendor, "Aruba") || MyStrcasestr(vendor, "Unifi") || MyStrcasestr(vendor, "Zyxel") || MyStrcasestr(vendor, "Cisco") || MyStrcasestr(vendor, "Dlink") || MyStrcasestr(vendor, "Tplink") || MyStrcasestr(vendor, "Neatgear")))) {
        *hasSwitchWifi = 1;
        strcat(switchWifi, hostDetails);
        return;
    }

    if ((os_name && MyStrcasestr(os_name, "windows")) || (vendor && (MyStrcasestr(vendor, "HP") || MyStrcasestr(vendor, "Hewlett Packard")))) {
        json_object *os_obj = NULL;
        int isHPandPort135 = 0;

        if (vendor && (MyStrcasestr(vendor, "HP") || MyStrcasestr(vendor, "Hewlett Packard"))) {
            if (json_object_object_get_ex(host_json, "Open Ports", &ports_obj)) {
                size_t n_ports = json_object_array_length(ports_obj);
                for (size_t i = 0; i < n_ports; i++) {
                    json_object *port = json_object_array_get_idx(ports_obj, i);
                    const char *port_str = json_object_get_string(port);
                    if (strstr(port_str, "135")) {
                        isHPandPort135 = 1;
                        break;
                    }
                }
            }
        }

        if (json_object_object_get_ex(host_json, "OS", &os_obj)) {
            const char *os_name = json_object_get_string(os_obj);
            
            if ((os_name && MyStrcasestr(os_name, "windows")) || isHPandPort135) {
                *hasPoste = 1;
                strcat(poste, hostDetails);
                return;
            }
        }
    }
    
    *hasOthers = 1;
    strcat(others, hostDetails);
}

void createHtml(json_object *jsonRoot, const char *htmlFilePath, int isVLAN, int vlan_id) {
    static FILE *file = NULL;
    static int isFirstCall = 1;
    char *firewalls = calloc(1, INITIAL_BUFFER_SIZE);
    char *servers = calloc(1, INITIAL_BUFFER_SIZE);
    char *switchWifi = calloc(1, INITIAL_BUFFER_SIZE);
    char *poste = calloc(1, INITIAL_BUFFER_SIZE);
    char *telephonie = calloc(1, INITIAL_BUFFER_SIZE);
    char *imprimantes = calloc(1, INITIAL_BUFFER_SIZE);
    char *others = calloc(1, INITIAL_BUFFER_SIZE);
    
    if (!firewalls || !servers || !switchWifi || !poste || !telephonie || !imprimantes || !others) {
        if (firewalls) free(firewalls);
        if (servers) free(servers);
        if (switchWifi) free(switchWifi);
        if (poste) free(poste);
        if (telephonie) free(telephonie);
        if (imprimantes) free(imprimantes);
        if (others) free(others);
        fprintf(stderr, RED "[✗] Memory allocation error\n"COLOR_RESET);
        return;
    }

    if (isFirstCall) {
        file = fopen(htmlFilePath, "w");
        if (file == NULL) {
            fprintf(stderr, RED"[✗] Error creating HTML file HTML\n"COLOR_RESET);
            free(firewalls);
            free(servers);
            free(switchWifi);
            free(poste);
            free(telephonie);
            free(imprimantes);
            free(others);
            return;
        }

        fprintf(file, "<!DOCTYPE html>\n<html lang=\"fr-FR\">");
        fprintf(file, "<meta charset=\"UTF-8\">\n");
        fprintf(file, "<title>Network Scan Report</title>\n</head>\n");
        fprintf(file, "<style>\n");
        fprintf(file, "@import url('https://fonts.googleapis.com/css2?family=Roboto:wght@400;700&display=swap');\n");
        fprintf(file, "body { font-family: 'Roboto', sans-serif; margin: 0; padding: 0; background-color: #000; color: #fff; }\n");
        fprintf(file, ".container { width: 65%%; margin: 0 auto; padding: 20px; background-color: #333; box-shadow: 0 0 20px rgba(0, 0, 0, 0.5); }\n");
        fprintf(file, "h1 { text-align: center; color:rgb(255, 255, 255); }\n");
        fprintf(file, ".heart-red { color: #FF0000; }\n");
        fprintf(file, ".max-black { color:rgb(255, 255, 255); }\n");
        fprintf(file, ".firewall-container, .server-container, .switch-wifi-container, .poste-container, .telephonie-container, .imprimante-container, .other-container { margin-bottom: 20px; background-color: #222; padding: 10px; border-radius: 8px; }\n");
        fprintf(file, ".firewall-container h2, .server-container h2, .switch-wifi-container h2, .poste-container h2, .telephonie-container h2, .imprimante-container h2, .other-container h2 { background-color:rgb(0, 97, 243); color: #000; padding: 10px; border-radius: 5px; }\n");
        fprintf(file, ".host { border: 1px solid #555; padding: 10px; margin-bottom: 10px; border-radius: 5px; background-color: #222; }\n");
        fprintf(file, ".host p { margin: 5px 0; }\n");
        fprintf(file, "a { color:rgb(0, 97, 243); text-decoration: none; }\n");
        fprintf(file, "a:hover { text-decoration: underline; color: #FFF; }\n");
        fprintf(file, "@media print { .container { width: 100%%; } }\n");
        fprintf(file, ".accordion { cursor: pointer; width: 100%%; border: none; text-align: left; outline: none; font-size: 20px; transition: 0.4s; }\n");
        fprintf(file, ".panel { display: none; overflow: hidden; }\n");
        fprintf(file, ".vlan-section, .nearby-section { margin-top: 30px; padding-top: 20px; border-top: 2px solid #444; }\n");
        fprintf(file, "</style>\n");
        fprintf(file, "<body>\n");
        fprintf(file, "<script src='https://code.jquery.com/jquery-3.5.1.min.js'></script>\n");
        fprintf(file, "<script>\n");
        fprintf(file, "$(document).ready(function(){\n");
        fprintf(file, "  $('.accordion').click(function(){\n");
        fprintf(file, "    this.classList.toggle('active');\n");
        fprintf(file, "    var panel = this.nextElementSibling;\n");
        fprintf(file, "    if (panel.style.display === 'block') {\n");
        fprintf(file, "      panel.style.display = 'none';\n");
        fprintf(file, "    } else {\n");
        fprintf(file, "      panel.style.display = 'block';\n");
        fprintf(file, "    }\n");
        fprintf(file, "  });\n");
        fprintf(file, "});\n");
        fprintf(file, "</script>\n");
        fprintf(file, "<div class='container'>\n");
        fprintf(file, "<h1>Network Scanner - <span class='max-black'>Enterprise</span><span class='heart-red'>X</span></h1>\n");
        isFirstCall = 0;
    } else {
        file = fopen(htmlFilePath, "a");
        if (file == NULL) {
            fprintf(stderr, RED"[✗] Error opening HTML file\n"COLOR_RESET);
            free(firewalls);
            free(servers);
            free(switchWifi);
            free(poste);
            free(telephonie);
            free(imprimantes);
            free(others);
            return;
        }
    }

    const char *networkAddress = NULL;
    if (json_object_array_length(jsonRoot) > 0) {
        json_object *firstHost = json_object_array_get_idx(jsonRoot, 0);
        json_object *networkObj;
        if (json_object_object_get_ex(firstHost, "Network", &networkObj)) {
            networkAddress = json_object_get_string(networkObj);
        }
    }

    if (isVLAN == 1) {
        fprintf(file, "<div class='vlan-section'>\n");
        fprintf(file, "<h2>VLAN %d</h2>\n", vlan_id);
    } else if (isVLAN == 3) {
        fprintf(file, "<div class='nearby-section'>\n");
        if (networkAddress) {
            fprintf(file, "<h2>Neighbouring network: %s</h2>\n", networkAddress);
        } else {
            fprintf(file, "<h2>Neighbouring networks</h2>\n");
        }
    }

    printf("...Improved job classification in progress...\n");

    int hasFirewalls = 0, hasServers = 0, hasSwitchWifi = 0, hasPoste = 0, hasTelephonie = 0, hasImprimantes = 0, hasOthers = 0; 

    size_t n_hosts = json_object_array_length(jsonRoot);

    for (size_t i = 0; i < n_hosts; i++) {
        json_object *host = json_object_array_get_idx(jsonRoot, i);

        json_object *ip_addr_obj, *os_obj, *vendor_obj, *mac_obj, *ports_obj, *hostname_obj, *network_obj, *network_type_obj;
        const char *ip_addr, *os_name = NULL, *vendor = NULL, *mac = NULL, *network = NULL, *network_type = NULL;
        int os_accuracy = -1;
        int webPort = -1;

        json_object_object_get_ex(host, "IP Address", &ip_addr_obj);
        json_object_object_get_ex(host, "OS", &os_obj);
        json_object_object_get_ex(host, "Vendor", &vendor_obj);
        json_object_object_get_ex(host, "MAC Address", &mac_obj);
        json_object_object_get_ex(host, "Open Ports", &ports_obj);
        json_object_object_get_ex(host, "Hostnames", &hostname_obj);
        json_object_object_get_ex(host, "Network", &network_obj);
        json_object_object_get_ex(host, "NetworkType", &network_type_obj);

        ip_addr = json_object_get_string(ip_addr_obj);
        vendor = json_object_get_string(vendor_obj);
        mac = json_object_get_string(mac_obj);
        os_name = json_object_get_string(os_obj);
        if (network_obj) network = json_object_get_string(network_obj);
        if (network_type_obj) network_type = json_object_get_string(network_type_obj);

        if (os_obj) {
            json_object *os_name_obj, *os_accuracy_obj;
            json_object_object_get_ex(os_obj, "Name", &os_name_obj);
            json_object_object_get_ex(os_obj, "Accuracy", &os_accuracy_obj);

            if (os_name_obj) {
                os_name = json_object_get_string(os_name_obj);
            }

            if (os_accuracy_obj) {
                os_accuracy = json_object_get_int(os_accuracy_obj);
            }
        }

        if (ports_obj) {
            size_t n_ports = json_object_array_length(ports_obj);
            for (size_t j = 0; j < n_ports; j++) {
                int port = atoi(json_object_get_string(json_object_array_get_idx(ports_obj, j)));
                if (port == 80 || port == 443 || port == 8080 || port == 8443 || port == 4444) {
                    webPort = port;
                    break;
                }
            }
        }

        char hostDetails[1024]; 
        int length = 0;

        length += snprintf(hostDetails + length, sizeof(hostDetails) - length, "<div class='host'>\n");
        
        if (webPort != -1) {
            const char *protocol = (webPort == 443 || webPort == 8443) ? "https" : "http";
            length += snprintf(hostDetails + length, sizeof(hostDetails) - length, 
                "<div class='accordion'>IP Address: <a href='%s://%s:%d' target='_blank'>%s</a>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;%s</div>", 
                protocol, ip_addr, webPort, ip_addr, vendor);
        } else {
            length += snprintf(hostDetails + length, sizeof(hostDetails) - length, 
                "<div class='accordion'>IP Address: %s&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;%s</div>\n", 
                ip_addr, vendor);
        }
        
        length += snprintf(hostDetails + length, sizeof(hostDetails) - length, "<div class='panel'>\n");

        if (os_name && os_accuracy >= 0) {
            length += snprintf(hostDetails + length, sizeof(hostDetails) - length, "<p>OS: %s %d%%<br>MAC Address: %s", os_name, os_accuracy, mac);
        } else {
            length += snprintf(hostDetails + length, sizeof(hostDetails) - length, "<p>OS: %s<br>MAC Address: %s", os_name, mac);
        }

        if (network && network_type) {
            length += snprintf(hostDetails + length, sizeof(hostDetails) - length, "<br>Network: %s (%s)", network, network_type);
        }

        if (ports_obj && json_object_array_length(ports_obj) > 0) {
            length += snprintf(hostDetails + length, sizeof(hostDetails) - length, "<br>Open Port: ");

            size_t n_ports = json_object_array_length(ports_obj);
            for (size_t j = 0; j < n_ports; j++) {
                if (length < sizeof(hostDetails)) {
                    length += snprintf(hostDetails + length, sizeof(hostDetails) - length, "%s", json_object_get_string(json_object_array_get_idx(ports_obj, j)));
                    if (j < n_ports - 1) {
                        length += snprintf(hostDetails + length, sizeof(hostDetails) - length, ", ");
                    }
                }
            }
            length += snprintf(hostDetails + length, sizeof(hostDetails) - length, "\n");
        }

        hostDetails[sizeof(hostDetails) - 1] = '\0';

        if (hostname_obj && json_object_array_length(hostname_obj) > 0) {
            strcat(hostDetails, "<br>Hostnames: ");
            size_t n_hostnames = json_object_array_length(hostname_obj);
            for (size_t j = 0; j < n_hostnames; j++) {
                strcat(hostDetails, json_object_get_string(json_object_array_get_idx(hostname_obj, j)));
                if (j < n_hostnames - 1) {
                    strcat(hostDetails, ", ");
                }
            }
            strcat(hostDetails, "</p>\n");
        }

        strcat(hostDetails, "</div>\n</div>\n");

        categorizeHost(os_name, vendor, host, &hasFirewalls, &hasServers, &hasSwitchWifi, &hasTelephonie, &hasPoste, &hasImprimantes, &hasOthers, firewalls, servers, switchWifi, telephonie, poste, imprimantes, others, hostDetails);
    }

    if (hasFirewalls) {
        fprintf(file, "<div class='firewall-container'><h2>Firewalls</h2>\n%s</div>\n", firewalls); 
    }
    if (hasServers) {
        fprintf(file, "<div class='server-container'><h2>Serveurs</h2>\n%s</div>\n", servers);
    }
    if (hasSwitchWifi) {
        fprintf(file, "<div class='switch-wifi-container'><h2>Switch & Wifi</h2>\n%s</div>\n", switchWifi);
    }
    if (hasPoste) {
        fprintf(file, "<div class='poste-container'><h2>Postes</h2>\n%s</div>\n", poste);
    }
    if (hasTelephonie) {
        fprintf(file, "<div class='telephonie-container'><h2>Téléphonie</h2>\n%s</div>\n", telephonie);
    }
    if (hasImprimantes) {
        fprintf(file, "<div class='imprimante-container'><h2>Imprimantes</h2>\n%s</div>\n", imprimantes);
    }
    if (hasOthers) {
        fprintf(file, "<div class='other-container'><h2>Autres</h2>\n%s</div>\n", others);
    }

    if (isVLAN == 1 || isVLAN == 3) {
        fprintf(file, "</div>\n");
    }

    fclose(file);

    free(firewalls);
    free(servers);
    free(switchWifi);
    free(poste);
    free(telephonie);
    free(imprimantes);
    free(others);

    if (isVLAN == 3) {
        file = fopen(htmlFilePath, "a");
        if (file != NULL) {
            fprintf(file, "</div>\n</body>\n</html>");
            fclose(file);
        printf(GREEN "[✓] HTML report generated. %s\n" COLOR_RESET, htmlFilePath);
        }
    }
}

void scanAndClassifyVLANHosts(struct json_object *parsed_json, const char *htmlFilePath) {
    struct json_object *vlans;
    if (!json_object_object_get_ex(parsed_json, "VLANs", &vlans)) {
        return;
    }

    size_t vlan_count = json_object_array_length(vlans);
    if (vlan_count == 0) {
        return;
    }

    printf("[+] Start scanning VLANs & create report\n");

    for (size_t i = 0; i < vlan_count; i++) {
        struct json_object *vlan = json_object_array_get_idx(vlans, i);
        struct json_object *activeHosts;
        int vlan_id;
        
        if (!json_object_object_get_ex(vlan, "ActiveHosts", &activeHosts)) {
            continue;
        }

        if (!json_object_is_type(activeHosts, json_type_array)) {
            continue;
        }

        vlan_id = json_object_get_int(json_object_object_get(vlan, "ID"));
        printf("[+] Configuration and scan of the current ‘YELLOW ’VLAN %d" COLOR_RESET "...\n", vlan_id);

        char vlan_interface[16];
        snprintf(vlan_interface, sizeof(vlan_interface), "vlan%d", vlan_id);
        
        char command[256];
        snprintf(command, sizeof(command), "ip link delete %s 2>/dev/null", vlan_interface);
        system(command);

        snprintf(command, sizeof(command), "ip link add link %s name %s type vlan id %d", interface, vlan_interface, vlan_id);
        if (system(command) != 0) {
            fprintf(stderr, RED "[✗] Error creating VLAN interface %d\n" COLOR_RESET, vlan_id);
            continue;
        }

        snprintf(command, sizeof(command), "ip link set dev %s up", vlan_interface);
        if (system(command) != 0) {
            fprintf(stderr, RED "[✗] Error activating VLAN interface %d\n" COLOR_RESET, vlan_id);
            continue;
        }

        printf("[+] Waiting for an IP address to be obtained on the ‘YELLOW ’VLAN %d‘ COLOR_RESET ’...\n", vlan_id);
        snprintf(command, sizeof(command), "dhclient %s", vlan_interface);
        system(command);
        sleep(5);

        char xml_file[256];
        char json_file[256];
        snprintf(xml_file, sizeof(xml_file), "./nmap_vlan_%d.xml", vlan_id);
        snprintf(json_file, sizeof(json_file), "./nmap_vlan_%d.json", vlan_id);

        scanAllHostsAndSaveToXML(activeHosts);

        rename("./nmap.xml", xml_file);
        
        readXMLAndSaveToJson(xml_file, json_file);

        struct json_object *jsonRoot = json_object_from_file(json_file);
        if (jsonRoot == NULL) {
            fprintf(stderr, RED "[✗] Error : Unable to read %s\n" COLOR_RESET, json_file);
            continue;
        }

        if (!json_object_is_type(jsonRoot, json_type_array)) {
            fprintf(stderr, RED "[✗] Error : The JSON content is not an array\n" COLOR_RESET);
            json_object_put(jsonRoot);
            continue;
        }

        createHtml(jsonRoot, htmlFilePath, 1, vlan_id);
        json_object_put(jsonRoot);

        remove(xml_file);
        remove(json_file);

        snprintf(command, sizeof(command), "ip link delete %s", vlan_interface);
        system(command);

        printf(GREEN "[✓] Scan of VLAN %d complete\n" COLOR_RESET, vlan_id);
    }
}

void restartNetworkManager() {
    printf(YELLOW "[+] Restarting NetworkManager...\n" COLOR_RESET);
    system("sudo systemctl stop NetworkManager");
    sleep(2);
    system("sudo systemctl start NetworkManager");
    sleep(2);
}

void signalHandler(int signum) {
    printf(RED"[✗] Interruption detected." COLOR_RESET "Network reset...\n");
    resetNetworkInterface(interface);
    printf(RED "End of programme\n" COLOR_RESET);
    exit(signum);
}

void cleanup() {
    resetNetworkInterface(interface);
    printf(RED "End of programme\n" COLOR_RESET);
}

char* str_replace(char *str, const char *old, const char *new) {
    static char buffer[1024];
    char *p;
    
    if (!(p = strstr(str, old))) {
        return str;
    }
    
    strncpy(buffer, str, p - str);
    buffer[p - str] = '\0';
    
    sprintf(buffer + (p - str), "%s%s", new, p + strlen(old));
    
    return buffer;
}

void scanNearbyNetworks(char *jsonFilePath) {
    struct json_object *parsed_json, *nearbyNetworks;
    char *networkAddress;

    parsed_json = json_object_from_file(jsonFilePath);
    if (!parsed_json) {
        printf(RED"[✗] Error reading JSON file\n" COLOR_RESET);
        return;
    }

    if (!json_object_object_get_ex(parsed_json, "NearbyNetworks", &nearbyNetworks)) {
        printf(RED"[✗] No neighbouring network found in the JSON file\n" COLOR_RESET);
        json_object_put(parsed_json);
        return;
    }

    size_t n_networks = json_object_array_length(nearbyNetworks);
    printf(YELLOW"[+] Start scanning neighbouring networks (%zu networks found)\n" COLOR_RESET, n_networks);

    struct json_object *allNearbyHosts = json_object_new_array();

    for (size_t i = 0; i < n_networks; i++) {
        struct json_object *network = json_object_array_get_idx(nearbyNetworks, i);
        struct json_object *address, *type;
        const char *networkType;

        if (json_object_object_get_ex(network, "NearbyNetworkAddress", &address)) {
            networkAddress = strdup(json_object_get_string(address));
            json_object_object_get_ex(network, "Type", &type);
            networkType = json_object_get_string(type);
        } else if (json_object_object_get_ex(network, "Network", &address)) {
            networkAddress = strdup(json_object_get_string(address));
            json_object_object_get_ex(network, "Type", &type);
            networkType = json_object_get_string(type);
        } else {
            continue;
        }

        printf(YELLOW"[+] Network scan %s (%s)\n" COLOR_RESET, networkAddress, networkType);
        
        char *slash24 = strstr(networkAddress, "/24");
        if (slash24) {
            *slash24 = '\0';
        }
        
        char network_with_mask[256];
        snprintf(network_with_mask, sizeof(network_with_mask), "%s/24", networkAddress);
        
        scanActiveHostsAndUpdateJSON(network_with_mask, jsonFilePath, -2, NULL);

        struct json_object *activeHosts;
        if (json_object_object_get_ex(network, "ActiveHosts", &activeHosts)) {
            if (json_object_array_length(activeHosts) > 0) {
                printf(YELLOW"[+] Port scanning for the network %s\n" COLOR_RESET, networkAddress);
                
                struct json_object *tempHosts = json_object_new_array();
                size_t n_hosts = json_object_array_length(activeHosts);
                
                for (size_t j = 0; j < n_hosts; j++) {
                    struct json_object *host = json_object_array_get_idx(activeHosts, j);
                    json_object_array_add(tempHosts, json_object_get(host));
                }
                
                scanAllHostsAndSaveToXML(tempHosts);
                readXMLAndSaveToJson("./nmap.xml", "./nmap_nearby.json");

                struct json_object *jsonRoot = json_object_from_file("./nmap_nearby.json");
                if (jsonRoot != NULL) {

                    size_t n_scanned_hosts = json_object_array_length(jsonRoot);
                    for (size_t j = 0; j < n_scanned_hosts; j++) {
                        struct json_object *host = json_object_array_get_idx(jsonRoot, j);
                        if (json_object_get_type(host) == json_type_object) {
                            json_object_object_add(host, "Network", json_object_new_string(networkAddress));
                            json_object_object_add(host, "NetworkType", json_object_new_string(networkType));

                            json_object_array_add(allNearbyHosts, json_object_get(host));
                        }
                    }
                    json_object_put(jsonRoot);
                }
                
                json_object_put(tempHosts);
                remove("./nmap.xml");
                remove("./nmap_nearby.json");
            }
        }

        free(networkAddress);
    }

    if (json_object_array_length(allNearbyHosts) > 0) {
        createHtml(allNearbyHosts, "./rapport.html", 3, 0);
    }

    json_object_put(allNearbyHosts);
    json_object_put(parsed_json);
    printf(GREEN"[✓] Scan of neighbouring networks complete\n" COLOR_RESET);
}

int main() {
    printf("\033[H\033[J");
    char *jsonFilePath = "./network_info.json";
    char *vlanJsonFilePath = "./network_info_vlan.json";

    get_network_interface_name(interface);

    signal(SIGINT, signalHandler);
    atexit(cleanup);
    printf(GREEN"[✓] Network interface detected : %s\n" COLOR_RESET, interface);

    changeMACAddressAndRenewIP(interface);
    char* networkAddress = getLocalNetworkAddress(jsonFilePath);
    
    scanActiveHostsAndUpdateJSON(networkAddress, jsonFilePath, -1, vlanJsonFilePath);
    free(networkAddress);

    processVLANs(interface, jsonFilePath);

    mergeAndDeleteJSONFiles("./network_info.json", "./network_info_vlan.json", "./network.json");

    changeMACAddressAndRenewIP(interface);

    struct json_object *parsed_json, *defaultNetwork, *activeHosts;
    printf("[+] Start DefaultNetwork scan & create report\n");

    parsed_json = json_object_from_file("./network.json");
    if (parsed_json == NULL) {
        fprintf(stderr, RED"[✗] Error: Unable to read ./network.json\n"COLOR_RESET);
        return 1;
    }

    if (!json_object_object_get_ex(parsed_json, "DefaultNetwork", &defaultNetwork)) {
        fprintf(stderr, RED "[✗] Error : 'DefaultNetwork' not found in JSON\n"COLOR_RESET);
        json_object_put(parsed_json);
        return 1;
    }

    if (!json_object_object_get_ex(defaultNetwork, "ActiveHosts", &activeHosts)) {
        fprintf(stderr, RED "[✗] Error : 'ActiveHosts' not found in 'DefaultNetwork'.\n"COLOR_RESET);
        json_object_put(parsed_json);
        return 1;
    }

    if (!json_object_is_type(activeHosts, json_type_array)) {
        fprintf(stderr, RED "[✗] Error : 'ActiveHosts' is not a JSON array\n"COLOR_RESET);
        json_object_put(parsed_json);
        return 1;
    }

    scanAllHostsAndSaveToXML(activeHosts);
    readXMLAndSaveToJson("./nmap.xml", "./nmap.json");

    struct json_object *jsonRoot = json_object_from_file("./nmap.json");
    if (jsonRoot == NULL) {
        fprintf(stderr, RED "[✗] Error : Unable to read ./nmap.json\n" COLOR_RESET);
        json_object_put(parsed_json);
        return 1;
    }

    if (!json_object_is_type(jsonRoot, json_type_array)) {
        fprintf(stderr, RED "Error : The JSON content is not an array\n" COLOR_RESET);
        json_object_put(jsonRoot);
        json_object_put(parsed_json);
        return 1;
    }

    createHtml(jsonRoot, "./report.html", 0, 0);
    json_object_put(jsonRoot);

    scanAndClassifyVLANHosts(parsed_json, "./report.html");

    scanNearbyNetworks("./network.json");

    json_object_put(parsed_json);
    return 0;
}
