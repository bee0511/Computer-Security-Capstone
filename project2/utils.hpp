#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()

#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_RAW
#include <netinet/ip.h>       // IP_MAXPACKET (which is 65535)
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <net/if.h>           // struct ifreq
#include <linux/if_ether.h>   // ETH_P_ARP = 0x0806
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <linux/if_arp.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

#include <errno.h>            // errno, perror()

#include <algorithm>
#include <cstdio>
#include <vector>
#include <map>
#include <array>
#include <span>
#include <chrono>
#include <thread>

void get_mac_address(const char *interface, std::array<uint8_t, 6> &src_mac);
void get_netmask(const char *interface, struct sockaddr_in &netmask);
void get_src_IP(const char *interface, struct sockaddr_in &ipv4);
void get_default_gateway(uint32_t &gateway_ip);