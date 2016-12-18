#ifndef __DPROTOCOL_H
#define __DPROTOCOL_H

#include "public.h"
#include <sys/types.h>
/*
	size_t
*/

#include <stdio.h> 
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <fcntl.h>
#include <time.h>

#define DOFFLINE         0
#define DONLINE          1

#define DR_SERVER_IP "202.38.210.131"
#define DR_PORT 61440
#define RECV_BUF_LEN 1500
#define D_TIMEOUT 3
#define RETRY_TIME 5


int drcom_pkt_id;
int dstatus;
char dstatusMsg[256];
char dsystemMsg[256];
char dUpdateAt[64];


void init_env_d();
int udp_recv(char* recv_buf);
int udp_send_and_rev(char* send_buf, int send_len, char* recv_buf);
void* serve_forever_d(void *args);

#endif
