#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <signal.h>
#include <time.h>
#include <ctype.h>

#define GREEN   "\x1b[32m"
#define YELLOW  "\x1b[33m"
#define RED     "\x1b[31m"
#define COLOR_RESET   "\x1b[0m"
#define MAX_VLAN 4096

typedef struct {
    unsigned int id;
    char network_addr[INET_ADDRSTRLEN];
} VlanInfo;

VlanInfo found_vlans[MAX_VLAN];
int vlan_count = 0;
int vlan_found = 0;
volatile sig_atomic_t stop_program = 0;

void handle_signal(int signal) {
    stop_program = 1;
}

void get_network_interface_name(char *interface_name) {
    FILE *fp = fopen("/proc/net/route", "r");
    if (fp == NULL) {
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

void get_public_ip(char *buffer) {
    FILE *fp = popen("curl -s ifconfig.me", "r");
    if (fp != NULL) {
        fgets(buffer, 100, fp);
        strtok(buffer, "\n");
        pclose(fp);
    } else {
        strcpy(buffer, "Error");
    }
}

void get_subnet_mask(char *interface_name, char *subnet_mask, char *prefix_len_str) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ip addr show %s | grep 'inet ' | awk '{print $2}'", interface_name);

    FILE *fp = popen(cmd, "r");
    if (fp == NULL) {
        strcpy(subnet_mask, "Error");
        return;
    }

    char buffer[256];
    if (fgets(buffer, sizeof(buffer), fp) != NULL) {
        char *slash = strchr(buffer, '/');
        if (slash != NULL) {
            int prefix_len = atoi(slash + 1);
            snprintf(prefix_len_str, 4, "%d", prefix_len);

            *slash = '\0';
            struct in_addr addr;
            inet_pton(AF_INET, buffer, &addr);
            addr.s_addr = htonl(~((1 << (32 - prefix_len)) - 1));
            inet_ntop(AF_INET, &addr, subnet_mask, INET_ADDRSTRLEN);
        }
    } else {
        strcpy(subnet_mask, "Unknown");
    }
    pclose(fp);
}

void get_network_address(const char *ip, const char *netmask, char *network_address) {
    struct in_addr ip_addr, netmask_addr, subnet_addr;

    inet_pton(AF_INET, ip, &ip_addr);
    inet_pton(AF_INET, netmask, &netmask_addr);

    subnet_addr.s_addr = ip_addr.s_addr & netmask_addr.s_addr;

    inet_ntop(AF_INET, &subnet_addr, network_address, INET_ADDRSTRLEN);
}

void get_my_ip(char *buffer) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    const char* dest = "8.8.8.8";
    uint16_t port = 53;

    struct sockaddr_in serv;
    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);

    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr(dest);
    serv.sin_port = htons(port);

    connect(sock, (const struct sockaddr*) &serv, sizeof(serv));
    getsockname(sock, (struct sockaddr*) &name, &namelen);

    inet_ntop(AF_INET, &name.sin_addr, buffer, 100);

    close(sock);
}

void get_default_gateway(char *buffer) {
    FILE *fp = popen("ip route | grep default | awk '{print $3}'", "r");
    if (fp != NULL) {
        fgets(buffer, 100, fp);
        strtok(buffer, "\n");
        pclose(fp);
    }
}

void get_dhcp_server(char *buffer, const char *interface) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "nmcli -f DHCP4.OPTION device show %s | grep dhcp_server_identifier | awk -F '=' '{print $2}'", interface);

    FILE *fp = popen(cmd, "r");
    if (fp != NULL) {
        if (fgets(buffer, 100, fp) == NULL) {
            strcpy(buffer, "Unknown");
        } else {
            strtok(buffer, "\n");
        }
        pclose(fp);
    } else {
        strcpy(buffer, "Error");
    }
}

void get_dns_server_nmcli(char *buffer, const char *interface_name) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "nmcli -t -f IP4.DNS device show %s | cut -d: -f2", interface_name);

    FILE *fp = popen(cmd, "r");
    if (fp != NULL) {
        fgets(buffer, 100, fp);
        strtok(buffer, "\n");
        pclose(fp);
    }
}

void perform_ping_tests(const char *gateway) {
    char cmd[256];
    int ret;

    snprintf(cmd, sizeof(cmd), "ping -c 1 %s > /dev/null 2>&1", gateway);
    ret = system(cmd);
    if (ret == 0) {
        printf("\033[32mPing to \033[0m%s : \033[32mOK\033[0m\n", gateway);
    } else {
        printf("\033[32mPing to \033[0m%s : \033[31mFAILED\033[0m\n", gateway);
    }

    ret = system("ping -c 1 1.1.1.1 > /dev/null 2>&1");
    if (ret == 0) {
        printf("\033[32mPing to \033[0m1.1.1.1 : \033[32mOK\033[0m\n");
    } else {
        printf("\033[32mPing to \033[0m1.1.1.1 : \033[31mFAILED\033[0m\n");
    }

    ret = system("ping -c 1 google.fr > /dev/null 2>&1");
    if (ret == 0) {
        printf("\033[32mPing to \033[0mgoogle.fr : \033[32mOK\033[0m\n");
    } else {
        printf("\033[32mPing to \033[0mgoogle.fr : \033[31mFAILED\033[0m\n");
    }
}

void get_switch_port() {
    FILE *fp;
    char path[1035];

    fp = popen("lldpctl", "r");
    if (fp == NULL) {
        printf("Failed to run command.\n");
        exit(1);
    }

    while (fgets(path, sizeof(path), fp) != NULL) {
        printf("%s", path);
    }

    pclose(fp);
}

char *run_command(const char *command) {
    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        return "Error running command.";
    }

    char *output = malloc(1024 * sizeof(char));
    fread(output, sizeof(char), 1024, fp);
    pclose(fp);

    return output;
}

void parse_lldp_output(char *output) {
    char *sysname = strstr(output, "SysName:");
    char *sysdescr = strstr(output, "SysDescr:");
    char *mgmtip = strstr(output, "MgmtIP:");
    char *portid = strstr(output, "PortID:");
    if (sysname) {
        sysname += strlen("SysName:");
        printf("Name :%.*s\n", strcspn(sysname, "\n"), sysname);
    }
    if (sysdescr) {
        sysdescr += strlen("SysDescr:");
        printf("Description :%.*s\n", strcspn(sysdescr, "\n"), sysdescr);
    }
    if (mgmtip) {
        mgmtip += strlen("MgmtIP:");
        printf("IP Address :%.*s\n", strcspn(mgmtip, "\n"), mgmtip);
    }
    if (portid) {
        portid += strlen("PortID:");
        printf("Port :%.*s\n", strcspn(portid, "\n"), portid);
    }
}

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    if (stop_program) {
        printf("\n" RED "Program interrupted by user.\n" COLOR_RESET);
        pcap_breakloop((pcap_t *)user_data);
        return;
    }

    static time_t last_time = 0;
    static time_t start_time = 0;
    static int first_call = 1;
    time_t current_time;

    if (first_call) {
        start_time = time(NULL);
        first_call = 0;
    }

    struct ether_header *eth_header;
    struct ip *ip_header;

    eth_header = (struct ether_header *) packet;

    if (ntohs(eth_header->ether_type) == ETHERTYPE_VLAN) {
        unsigned int vlan_tag = (unsigned int) ntohs(*(unsigned short *)(packet + 14));
        unsigned int vlan_id = vlan_tag & 0x0FFF;
        static int first_vlan = 1;
        int found = 0;
        for (int i = 0; i < vlan_count; ++i) {
            if (found_vlans[i].id == vlan_id) {
                found = 1;
                break;
            }
        }

        if (!found) {
            if (pkthdr->len >= 18 + sizeof(struct ip)) {
                ip_header = (struct ip *)(packet + 18);
                char src_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);

                found_vlans[vlan_count].id = vlan_id;
                snprintf(found_vlans[vlan_count].network_addr, INET_ADDRSTRLEN, "%s", src_ip);
                ++vlan_count;

                printf(YELLOW "VLAN ID:" COLOR_RESET " %u\n", vlan_id);

                FILE *fp = fopen("./network_info.json", "a");
                if (fp == NULL) {
                    perror("Error opening file");
                    return;
                }

                if (!first_vlan) {
                    fprintf(fp, ",\n");
                } else {
                    first_vlan = 0;
                }

                fprintf(fp, "    {\n");
                fprintf(fp, "      \"ID\": %u,\n", vlan_id);
                fprintf(fp, "      \"VLANNetworkAddress\": \"%s\",\n", src_ip);
                fprintf(fp, "      \"ActiveHosts\": []\n");
                fprintf(fp, "    }");

                fclose(fp);
            }
            vlan_found = 1;
            last_time = time(NULL);
        }
    }

    current_time = time(NULL);

    if (vlan_count > 0 && (current_time - last_time >= 35)) {
        printf("\n");
        printf(RED "No new VLAN found in the last 35 seconds. Stopping VLAN search.\n" COLOR_RESET);
        printf("\n");
        pcap_breakloop((pcap_t *)user_data);
        return;
    }

    if (vlan_count == 0 && (current_time - start_time >= 60)) {
        printf("\n");
        printf(RED "No VLAN found in the first 60 seconds. Stopping VLAN search.\n" COLOR_RESET);
        printf("\n");
        pcap_breakloop((pcap_t *)user_data);
        return;
    }
}

void save_initial_info(const char *gateway_ip, const char *dns_server, const char *dhcp_server, const char *local_network_address) {
    // Supprimer le fichier s'il existe
    remove("./network_info.json");
    
    FILE *fp = fopen("./network_info.json", "w");
    if (fp == NULL) {
        perror("Error opening file");
        return;
    }

    fprintf(fp, "{\n");
    fprintf(fp, "  \"DefaultNetwork\": {\n");
    fprintf(fp, "    \"GatewayIP\": \"%s\",\n", gateway_ip);
    fprintf(fp, "    \"DNSServer\": \"%s\",\n", dns_server);
    fprintf(fp, "    \"DHCPServer\": \"%s\",\n", dhcp_server);
    fprintf(fp, "    \"LocalNetworkAddress\": \"%s\",\n", local_network_address);
    fprintf(fp, "    \"ActiveHosts\": []\n");
    fprintf(fp, "  },\n");
    fprintf(fp, "  \"VLANs\": [\n");
    fclose(fp);
}

void scanNearbyNetworks(const char *local_ip, const char *gateway) {
    char command[256];
    char network_prefix[32];
    FILE *json_file;
    char switch_ip[INET_ADDRSTRLEN] = {0};
    int first_network = 1;
    
    // Ouvrir la section NearbyNetworks
    json_file = fopen("./network_info.json", "a");
    if (json_file != NULL) {
        fprintf(json_file, "\n  ],\n");  // Fermer la section VLANs
        fprintf(json_file, "  \"NearbyNetworks\": [\n");
        fclose(json_file);
    }
    
    // Récupérer l'IP du switch depuis LLDP
    FILE *fp = popen("lldpctl | grep 'MgmtIP:' | awk '{print $2}'", "r");
    if (fp != NULL) {
        if (fgets(switch_ip, INET_ADDRSTRLEN, fp) != NULL) {
            switch_ip[strcspn(switch_ip, "\n")] = 0; // Enlever le retour à la ligne
        }
        pclose(fp);
    }
    
    // Extraire le préfixe réseau (ex: 10.64)
    char *first_dot = strchr(local_ip, '.');
    char *second_dot = strchr(first_dot + 1, '.');
    if (first_dot && second_dot) {
        strncpy(network_prefix, local_ip, second_dot - local_ip);
        network_prefix[second_dot - local_ip] = '\0';
    } else {
        strcpy(network_prefix, local_ip);
    }

    printf(YELLOW "...Search for accessible subnets...\n" COLOR_RESET);
    
    // Vérifier d'abord le réseau du switch si on a son IP
    if (strlen(switch_ip) > 0) {
        // Extraire le préfixe réseau du switch
        char *last_dot = strrchr(switch_ip, '.');
        if (last_dot) {
            *last_dot = '\0';
            sprintf(command, "ping -c 1 -W 1 %s.1 > /dev/null 2>&1", switch_ip);
            if (system(command) == 0) {
                printf(GREEN "Accessible network : %s.0/24\n" COLOR_RESET, switch_ip);
                
                // Ajouter le réseau du switch au JSON
                json_file = fopen("./network_info.json", "a");
                if (json_file != NULL) {
                    if (!first_network) {
                        fprintf(json_file, ",\n");
                    }
                    fprintf(json_file, "    {\n");
                    fprintf(json_file, "      \"NearbyNetworkAddress\": \"%s.0/24\",\n", switch_ip);
                    fprintf(json_file, "      \"Type\": \"Switch Network\",\n");
                    fprintf(json_file, "      \"ActiveHosts\": []\n");
                    fprintf(json_file, "    }");
                    first_network = 0;
                    fclose(json_file);
                }
            }
        }
    }

    // Ajouter ensuite le réseau actuel
    json_file = fopen("./network_info.json", "a");
    if (json_file != NULL) {
        if (!first_network) {
            fprintf(json_file, ",\n");
        }
        fprintf(json_file, "    {\n");
        fprintf(json_file, "      \"Network\": \"%s.%d.0/24\",\n", 
                network_prefix, 
                atoi(strrchr(local_ip, '.') + 1));
        fprintf(json_file, "      \"Type\": \"Current Network\",\n");
        fprintf(json_file, "      \"ActiveHosts\": []\n");
        fprintf(json_file, "    }");
        first_network = 0;
        fclose(json_file);
    }

    // Scanner tous les réseaux possibles de 10.64.0.0 à 10.64.255.0
    printf(YELLOW "...Network scanning %s.0.0 à %s.255.0...\n" COLOR_RESET, network_prefix, network_prefix);
    
    for (int i = 0; i <= 255; i++) {
        // Ne pas scanner le réseau actuel
        if (i == atoi(strrchr(local_ip, '.') + 1)) {
            continue;
        }

        sprintf(command, "ping -c 1 -W 1 %s.%d.1 > /dev/null 2>&1", network_prefix, i);
        if (system(command) == 0) {
            printf(GREEN "Accessible network : %s.%d.0/24\n" COLOR_RESET, network_prefix, i);
            
            // Ajouter le réseau au JSON
            json_file = fopen("./network_info.json", "a");
            if (json_file != NULL) {
                if (!first_network) {
                    fprintf(json_file, ",\n");
                }
                fprintf(json_file, "    {\n");
                fprintf(json_file, "      \"NearbyNetworkAddress\": \"%s.%d.0/24\",\n", network_prefix, i);
                fprintf(json_file, "      \"Type\": \"Adjacent Network\",\n");
                fprintf(json_file, "      \"ActiveHosts\": []\n");
                fprintf(json_file, "    }");
                first_network = 0;
                fclose(json_file);
            }
        }
    }
    
    printf(GREEN "Subnet search complete\n" COLOR_RESET);
}

void finalize_json_file() {
    FILE *fp = fopen("./network_info.json", "a");
    if (fp == NULL) {
        perror("Error opening file");
        return;
    }

    // Fermer la section NearbyNetworks et le fichier JSON
    fprintf(fp, "\n  ]\n");
    fprintf(fp, "}\n");
    fclose(fp);
}

int main() {
    char interface[50];
    char public_ip[100];
    char my_ip[100];
    char subnet_mask[INET_ADDRSTRLEN];
    char prefix_len[4];
    char network_address[INET_ADDRSTRLEN];
    char gateway[100];
    char dns_server[100];
    char dhcp_server[100];
    char response[10];

    signal(SIGINT, handle_signal);

    // Supprimer le fichier JSON existant avant de commencer
    remove("./network_info.json");

    get_network_interface_name(interface);
    get_public_ip(public_ip);
    get_my_ip(my_ip);
    get_subnet_mask(interface, subnet_mask, prefix_len);
    get_network_address(my_ip, subnet_mask, network_address);
    get_default_gateway(gateway);
    get_dns_server_nmcli(dns_server, interface);
    get_dhcp_server(dhcp_server, interface);

    // Initialiser le fichier JSON avec les informations de base
    save_initial_info(gateway, dns_server, dhcp_server, network_address);

    printf("\n" GREEN "Network Information:" COLOR_RESET "\n");
    printf("Network Interface: %s\n", interface);
    printf("Public IP: %s\n", public_ip);
    printf("Local IP: %s\n", my_ip);
    printf("Network Address: %s\n", network_address);
    printf("Default Gateway: %s\n", gateway);
    printf("DNS Server: %s\n", dns_server);
    printf("DHCP Server: %s\n", dhcp_server);

    printf("\n" GREEN "Switch Information:" COLOR_RESET "\n");
    char *lldp_output = run_command("lldpctl");
    parse_lldp_output(lldp_output);
    free(lldp_output);

    printf("\n");
    perform_ping_tests(gateway);

    // Demander si l'utilisateur veut chercher les VLANs
    printf("\nDo you want to start VLAN search (~60sec)? (y/n): ");
    fflush(stdout);
    if (fgets(response, sizeof(response), stdin) != NULL) {
        response[0] = tolower(response[0]);
        if (response[0] == 'y') {
            char errbuf[PCAP_ERRBUF_SIZE];
            pcap_t *handle;
            struct bpf_program fp;
            char filter[] = "vlan";
            bpf_u_int32 net;

            printf(YELLOW "...Starting VLAN search...\n" COLOR_RESET);

            handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
            if (handle == NULL) {
                fprintf(stderr, RED "Couldn't open device %s: %s\n" COLOR_RESET, interface, errbuf);
                return(2);
            }

            if (pcap_compile(handle, &fp, filter, 0, net) == -1) {
                fprintf(stderr, RED "Couldn't parse filter %s: %s\n" COLOR_RESET, filter, pcap_geterr(handle));
                return(2);
            }

            if (pcap_setfilter(handle, &fp) == -1) {
                fprintf(stderr, RED "Couldn't install filter %s: %s\n" COLOR_RESET, filter, pcap_geterr(handle));
                return(2);
            }

            pcap_loop(handle, -1, packet_handler, (u_char *)handle);

            pcap_freecode(&fp);
            pcap_close(handle);
        } else {
            printf(RED "VLAN search canceled. " COLOR_RESET);
        }
    }

    // Demander si l'utilisateur veut chercher les sous-réseaux proches
    printf("\nDo you want to start Nearby Networks search (~240sec)? (y/n): ");
    fflush(stdout);
    if (fgets(response, sizeof(response), stdin) != NULL) {
        response[0] = tolower(response[0]);
        if (response[0] == 'y') {
            scanNearbyNetworks(my_ip, gateway);
            finalize_json_file();  // Fermer le fichier JSON une seule fois à la fin
        } else {
            printf(RED "Network search canceled. Stopping program.\n" COLOR_RESET);
            return 0;
        }
    }

    return 0;
}
