#include "utils.hpp"


uint8_t *cal_base_ip(uint8_t *ip, sockaddr_in &netmask) {
    // return base ip
    uint8_t *base_ip = (uint8_t *)malloc(4 * sizeof(uint8_t));
    uint8_t *mask_addr = (uint8_t *)&netmask.sin_addr.s_addr;
    for (int i = 0; i < 4; i++) {
        base_ip[i] = ip[i] & mask_addr[i];
    }
    return base_ip;
}

void get_default_gateway(uint8_t gateway_ip[4]) {
    FILE *fp = fopen("gateway.txt", "r");
    if (fp == nullptr) {
        perror("fopen() failed");
        exit(EXIT_FAILURE);
    }

    int res = fscanf(fp, "%hhu.%hhu.%hhu.%hhu", &gateway_ip[0], &gateway_ip[1], &gateway_ip[2], &gateway_ip[3]);
    if (res != 4) {
        perror("fscanf() failed");
        exit(EXIT_FAILURE);
    }

    fclose(fp);
}

void get_src_IP(const char *interface, struct sockaddr_in &ipv4) {
    int sd;
    struct ifreq ifr;

    // Submit request for a socket descriptor to look up interface.
    if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("socket() failed to get socket descriptor for using ioctl()");
        exit(EXIT_FAILURE);
    }

    // Use ioctl() to look up interface name and get its IPv4 address.
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface);
    if (ioctl(sd, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl() failed to get source IP address");
        return;
    }

    // Copy source IP address.
    memcpy(&ipv4, &ifr.ifr_addr, sizeof(struct sockaddr_in));

    close(sd);
}

void get_mac_address(const char *interface, uint8_t *src_mac) {
    int sd;
    struct ifreq ifr;

    // Submit request for a socket descriptor to look up interface.
    if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("socket() failed to get socket descriptor for using ioctl()");
        exit(EXIT_FAILURE);
    }

    // Use ioctl() to look up interface name and get its MAC address.
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface);
    if (ioctl(sd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl() failed to get source MAC address");
        return;
    }
    // Copy source MAC address.
    memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof(uint8_t));

    close(sd);
    return;
}

void get_netmask(const char *interface, struct sockaddr_in &netmask) {
    struct ifreq ifr;
    int sd;

    // Submit request for a socket descriptor to look up interface.
    if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("socket() failed to get socket descriptor for using ioctl()");
        exit(EXIT_FAILURE);
    }

    // Use ioctl() to look up interface name and get its netmask.
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface);
    if (ioctl(sd, SIOCGIFNETMASK, &ifr) < 0) {
        perror("ioctl() failed to get netmask");
        exit(EXIT_FAILURE);
    }

    // Copy netmask.
    memcpy(&netmask, &ifr.ifr_netmask, sizeof(struct sockaddr_in));

    close(sd);
}
