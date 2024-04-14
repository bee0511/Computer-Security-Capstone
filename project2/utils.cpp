#include "utils.hpp"

void get_default_gateway(uint32_t &gateway_ip) {
    FILE *fp = fopen("gateway.txt", "r");
    if (fp == nullptr) {
        perror("fopen() failed");
        exit(EXIT_FAILURE);
    }

    char ip_str[16];
    if (fgets(ip_str, sizeof(ip_str), fp) == nullptr) {
        perror("fgets() failed");
        exit(EXIT_FAILURE);
    }
    ip_str[strcspn(ip_str, "\n")] = 0;  // Remove newline character

    // printf("Gateway IP: %s\n", ip_str);

    if (inet_pton(AF_INET, ip_str, &gateway_ip) != 1) {
        perror("inet_pton() failed");
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

void get_mac_address(const char *interface, std::array<uint8_t, 6> &src_mac) {
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
        close(sd);
        return;
    }

    // Copy source MAC address.
    std::copy(ifr.ifr_hwaddr.sa_data, ifr.ifr_hwaddr.sa_data + 6, src_mac.begin());

    close(sd);
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
