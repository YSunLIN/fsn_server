#ifndef __PUBLIC_H_
#define __PUBLIC_H_

#include <stdint.h>
#include <stdio.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netpacket/packet.h> 


#define PASSWDFILE "/etc/scut_8021x.conf"


char user_id[32];
char passwd[32];
char interface_name[32];
char listen_ip[32];
int listen_port;

struct sockaddr_in my_ip;
char my_mac[ETH_ALEN];


void get_from_file(char *);
void print_mac(char *src);
void print_hex(char *hex, int len);
int checkCPULittleEndian();
uint32_t big2little_32(uint32_t A);

#endif