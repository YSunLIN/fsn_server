#include "dprotocol.h"
#include "xprotocol.h"


char drcom_challenge[4];
char drcom_keepalive_info[4];
char drcom_keepalive_info2[16];
char drcom_misc1_flux[4];
char drcom_misc3_flux[4];


static int  sock;
static struct sockaddr_in clientaddr;
static struct sockaddr_in drcomaddr;


uint32_t drcom_crc32(char *data, int data_len)
{
    uint32_t ret = 0;
    for (int i = 0; i < data_len;) {
        ret ^= *(unsigned int *) (data + i);
        ret &= 0xFFFFFFFF;
        i += 4;
    }

    // 大端小端的坑
    if(checkCPULittleEndian() == 0) ret = big2little_32(ret);
    ret = (ret * 19680126) & 0xFFFFFFFF;
    if(checkCPULittleEndian() == 0) ret = big2little_32(ret);

    return ret;
}


int start_request()
{
    const int pkt_data_len = 8;
    char pkt_data[8] =
        { 0x07, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00 };

    char revData[RECV_BUF_LEN];
    memset(revData, 0, RECV_BUF_LEN);
    int revLen =
        udp_send_and_rev(pkt_data, pkt_data_len, revData);
    // print_hex(revData, revLen);
    if(revLen < 0) return -1;

    if (revData[0] != 0x07) // Start Response
        return -1;

    memcpy(drcom_challenge, revData + 8, 4);    // Challenge

    // print_hex(drcom_challenge, 4);
    return 0;
}


int send_login_auth()
{
    const int pkt_data_len = 244;
    char pkt_data[pkt_data_len];

    memset(pkt_data, 0, pkt_data_len);
    int data_index = 0;

    // header
    pkt_data[data_index++] = 0x07;  // Code
    pkt_data[data_index++] = 0x01;  //id
    pkt_data[data_index++] = 0xf4;  //len(244低位)
    pkt_data[data_index++] = 0x00;  //len(244高位)
    pkt_data[data_index++] = 0x03;  //step 第几步
    pkt_data[data_index++] = strlen(user_id);   //uid len  用户ID长度

    // mac
    memcpy(pkt_data + data_index, my_mac, 6);
    data_index += 6;

    // ip
    memcpy(pkt_data + data_index, &my_ip.sin_addr, 4);
    data_index += 4;

    // fix(4B)
    pkt_data[data_index++] = 0x02;
    pkt_data[data_index++] = 0x22;
    pkt_data[data_index++] = 0x00;
    pkt_data[data_index++] = 0x2a;

    // challenge
    memcpy(pkt_data + data_index, drcom_challenge, 4);
    data_index += 4;

    // crc32(后面再填)
    pkt_data[data_index++] = 0xc7;  // = 20000711
    pkt_data[data_index++] = 0x2f;
    pkt_data[data_index++] = 0x31;
    pkt_data[data_index++] = 0x01;

    // 做完crc32后，在把第一个字节置位0
    pkt_data[data_index++] = 0x7e;  // = 126
    pkt_data[data_index++] = 0x00;
    pkt_data[data_index++] = 0x00;
    pkt_data[data_index++] = 0x00;

    // 0x0020  帐号 + 计算机名
    int user_id_length = strlen(user_id);
    memcpy(pkt_data + data_index, user_id, user_id_length); 
    data_index += user_id_length;
    char temp[100];
    memset(temp, 0, 100);
    strcpy(temp, "PC-");
    strcat(temp, user_id);
    memcpy(pkt_data + data_index, temp, 32 - user_id_length);
    data_index += (32 - user_id_length);

    //0x0040  dns 1 (114.114.114.114)
    data_index += 12;
    pkt_data[data_index++] = 0x72;
    pkt_data[data_index++] = 0x72;
    pkt_data[data_index++] = 0x72;
    pkt_data[data_index++] = 0x72;

    //0x0050
    data_index += 16;

    //0x0060
    pkt_data[data_index++] = 0x94;
    data_index += 3;
    pkt_data[data_index++] = 0x06;
    data_index += 3;
    pkt_data[data_index++] = 0x02;
    data_index += 3;
    pkt_data[data_index++] = 0xf0;
    pkt_data[data_index++] = 0x23;
    data_index += 2;

    //0x0070
    pkt_data[data_index++] = 0x02;
    data_index += 3;

    char drcom_ver[12] =
        { 0x44, 0x72, 0x43, 0x4f, 0x4d, 0x00, 0x96, 0x02, 0x2a, 0x00,
   0x00, 0x00 };
    memcpy(pkt_data + data_index, drcom_ver, 12);
    data_index += 12;   //

    //0x0080
    // pkt_data[data_index] = 0x00;
    // pkt_data[data_index + 1] = 0x00;
    data_index += 16;

    //0x0090
    data_index += 32;

    //0x00b0
    data_index += 4;
    char hashcode[] = "2ec15ad258aee9604b18f2f8114da38db16efd00";
    memcpy(pkt_data + data_index, hashcode, 40);
    data_index += 24;

    char revData[RECV_BUF_LEN];
    memset(revData, 0, RECV_BUF_LEN);

    unsigned int crc = drcom_crc32(pkt_data, pkt_data_len);
    // print_hex((char *) &crc, 4);

    memcpy(pkt_data + 24, (char *) &crc, 4);
    memcpy(drcom_keepalive_info, (char *) &crc, 4);
    // 完成crc32校验，置位0
    pkt_data[28] = 0x00;

    // print_hex(pkt_data,pkt_data_len);
    int revLen =
        udp_send_and_rev(pkt_data, pkt_data_len, revData);
    // print_hex(revData, revLen);
    if(revLen < 0) return -1;

    unsigned char *keepalive_info = revData + 16;
    for (int i = 0; i < 16; i++) {
        drcom_keepalive_info2[i] =
            (unsigned char) ((keepalive_info[i] << (i & 0x07)) +
                     (keepalive_info[i] >>
                      (8 - (i & 0x07))));
    }
    // print_hex(drcom_keepalive_info2, 16);
    return 0;
}


int send_alive_pkt1()
{
    const int pkt_data_len = 40;
    char pkt_data[pkt_data_len];

    memset(pkt_data, 0, pkt_data_len);
    int data_index = 0;
    pkt_data[data_index++] = 0x07;  // Code
    pkt_data[data_index++] = drcom_pkt_id; //id
    pkt_data[data_index++] = 0x28;  //len(40低位)
    pkt_data[data_index++] = 0x00;  //len(40高位)
    pkt_data[data_index++] = 0x0B;  // Step
    pkt_data[data_index++] = 0x01;

    pkt_data[data_index++] = 0xdc;  // Fixed Unknown
    pkt_data[data_index++] = 0x02;

    pkt_data[data_index++] = 0x00;  //每次加一个数
    pkt_data[data_index++] = 0x00;

    memcpy(pkt_data + 16, drcom_misc1_flux, 4);

    char revData[RECV_BUF_LEN];
    memset(revData, 0, RECV_BUF_LEN);
    int revLen =
        udp_send_and_rev(pkt_data, pkt_data_len, revData);
    // print_hex(revData, revLen);
    if(revLen < 0) return -1;


    if (revData[0] != 0x07 && revData[0] !=0x4d)    // Misc
        return -1;

    if (revData[5] == 0x06)   // File
    {
        return send_alive_pkt1();
    }
    else if(revData[0] == 0x4d)  // Message
    {
        printf("Drcom Server Message: %s\n", revData + 4);
        revData[sizeof(dsystemMsg)] = 0; 
        strcpy(dsystemMsg, revData + 4);
        revLen = udp_send_and_rev(NULL, 0, revData);
        if(revLen < 0) return -1;
    }

    drcom_pkt_id++;
    memcpy(&drcom_misc3_flux, revData + 16, 4);
    return 0;
}


int send_alive_pkt2()
{
    const int pkt_data_len = 40;
    char pkt_data[pkt_data_len];

    memset(pkt_data, 0, pkt_data_len);
    int data_index = 0;
    pkt_data[data_index++] = 0x07;  // Code
    pkt_data[data_index++] = drcom_pkt_id;
    pkt_data[data_index++] = 0x28;  //len(40低位)
    pkt_data[data_index++] = 0x00;  //len(40高位)

    pkt_data[data_index++] = 0x0B;  // Step
    pkt_data[data_index++] = 0x03;

    pkt_data[data_index++] = 0xdc;  // Fixed Unknown
    pkt_data[data_index++] = 0x02;

    pkt_data[data_index++] = 0x00;  //每次加一个数
    pkt_data[data_index++] = 0x00;


    memcpy(pkt_data + 16, drcom_misc3_flux, 4);
    memcpy(pkt_data + 28, &my_ip.sin_addr, 4);

    char revData[RECV_BUF_LEN];
    memset(revData, 0, RECV_BUF_LEN);
    int revLen =
        udp_send_and_rev(pkt_data, pkt_data_len, revData);
    // print_hex(revData, revLen);
    if(revLen < 0) return -1;

    drcom_pkt_id++;

    memcpy(drcom_misc1_flux, revData + 16, 4);
    return 0;

}


int send_alive_begin()      //keepalive
{
    const int pkt_data_len = 38;
    char pkt_data[pkt_data_len];
    memset(pkt_data, 0, pkt_data_len);
    int data_index = 0;

    pkt_data[data_index++] = 0xff;  // Code

    memcpy(pkt_data + data_index, drcom_keepalive_info, 16);
    data_index += 19;

    memcpy(pkt_data + data_index, drcom_keepalive_info2, 16);
    data_index += 16;

    char revData[RECV_BUF_LEN];
    memset(revData, 0, RECV_BUF_LEN);
    int revLen =
        udp_send_and_rev(pkt_data, pkt_data_len, revData);
    if(revLen < 0) return -1;

    return 0;

}


// init socket
void init_env_d()
{
    memset(&clientaddr, 0, sizeof(clientaddr));
    clientaddr.sin_family = AF_INET;
    clientaddr.sin_port = htons(DR_PORT);
    clientaddr.sin_addr = my_ip.sin_addr;

    memset(&drcomaddr, 0, sizeof(drcomaddr));
    drcomaddr.sin_family = AF_INET;
    drcomaddr.sin_port = htons(DR_PORT);
    inet_pton(AF_INET, DR_SERVER_IP, &drcomaddr.sin_addr);

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if( -1 == sock)
    {
        perror("Create drcom socket failed");
        exit(-1);
    }

    if( 0 != bind(sock, (struct sockaddr *) &clientaddr, sizeof(clientaddr)))
    {
        perror("Bind drcom sock failed");
        exit(-1);
    }

    // 设置超时时间
    struct timeval recv_ti, send_ti;   
    send_ti.tv_sec = recv_ti.tv_sec = D_TIMEOUT;
    send_ti.tv_usec = recv_ti.tv_usec = 0;
    setsockopt(sock,SOL_SOCKET, SO_RCVTIMEO, &recv_ti, sizeof(recv_ti));
    setsockopt(sock,SOL_SOCKET, SO_SNDTIMEO, &send_ti, sizeof(send_ti));
}


int udp_send_and_rev(char* send_buf, int send_len, char* recv_buf)
{
    int nrecv_send, addrlen = sizeof(struct sockaddr_in);
    struct sockaddr_in clntaddr;
    int try_times = RETRY_TIME;

    // 有内容才发
    while(send_len && try_times--){
        nrecv_send = sendto(sock, send_buf, send_len, 0, (struct sockaddr *) &drcomaddr, addrlen);
        if(nrecv_send == send_len) break;
    }

    try_times = RETRY_TIME;
    while(try_times--){
        nrecv_send = recvfrom(sock, recv_buf, RECV_BUF_LEN, 0,
                (struct sockaddr*) &clntaddr, &addrlen);
        if(nrecv_send > 0 && memcmp(&clntaddr.sin_addr, &drcomaddr.sin_addr, 4) == 0) break;
    }

    return nrecv_send;
}


static void perrorAndSleep(char* str){
    printf("%s\n", str);
    strcpy(dstatusMsg, str);
    dstatus = DOFFLINE;
    // 更新时间
    get_ctime(dUpdateAt, sizeof(dUpdateAt));
    sleep(5);
}

static void printAll(char* str){
    printf("drcom %s\n", str);
    strcpy(dstatusMsg, str);
}


void* serve_forever_d(void *args)
{
    int old_xstatus = XOFFLINE;
    int ret;
    int login_fail_count = 0;
    int xloginWait;

    drcom_pkt_id = 0;
    dstatus = DOFFLINE;
    strcpy(dstatusMsg, "none");
    strcpy(dsystemMsg, "none");
    // 更新时间
    get_ctime(dUpdateAt, sizeof(dUpdateAt));

    while(1){
        sleep(2);
        // 没登录就继续等待
        if(!is_login) continue;

        if(old_xstatus != xstatus){
            old_xstatus = xstatus;
            if(xstatus == XONLINE && dstatus == DOFFLINE){
                printAll("login = start request");
                ret = start_request();
                if(ret != 0){
                    perrorAndSleep("login = start request error");
                    continue;
                }

                sleep(1);
                printAll("login = send_login_auth");
                ret = send_login_auth();
                if(ret != 0){
                    perrorAndSleep("login = login error");
                    continue;
                }

                sleep(1);
                printAll("login = send_alive_pkt1");
                ret = send_alive_pkt1();
                if(ret != 0){
                    perrorAndSleep("login = alive phase 1 error");
                    continue;
                }

                printAll("login = send_alive_pkt2");
                ret = send_alive_pkt2();
                if(ret != 0){
                    perrorAndSleep("login = alive phase 2 error");
                    continue;
                }

                printAll("login successfully");
                dstatus = DONLINE;
                // 更新时间
                get_ctime(dUpdateAt, sizeof(dUpdateAt));
                sleep(10);
                continue;
            }
            // 这里没有continue
        }

        // 检测掉线
        if(xstatus == XOFFLINE || dstatus == DOFFLINE){
            if(xstatus == XOFFLINE){
                // 失败两次以上，就用广播
                login_fail_count++;
                if(login_fail_count > 2){
                    x_is_broadcast = 1;
                    printAll("xprotocol = using broastcast");
                    login_fail_count = 0;
                }
                else{
                    x_is_broadcast = 0;
                    printAll("xprotocol = using multicast");
                }
            }
            logoff();
            logoff();
            logon();
            // 防止sleep造成无法捕捉到边缘触发
            old_xstatus = xstatus = XOFFLINE;
            dstatus = DOFFLINE;
            xloginWait = 0;
            // 尝试等久点，由于何健明的bug
            while(xstatus != XONLINE && xloginWait < 10){
                sleep(1);
                xloginWait += 1;
            }
            // 前面已经sleep过了
            continue;
        }
        else if(xstatus == XONLINE && dstatus == DONLINE){
            printAll("keep = send_alive_begin");
            ret = send_alive_begin();
            if(ret != 0){
                perrorAndSleep("keep = begin alive error");
                continue;
            }
            
            printAll("keep = send_alive_pkt1");
            ret = send_alive_pkt1();
            if(ret != 0){
                perrorAndSleep("keep = alive phase 1 error");
                continue;
            }

            printAll("keep = send_alive_pkt2");
            ret = send_alive_pkt2();
            if(ret != 0){
                perrorAndSleep("keep = alive phase 2 error");
                continue;
            }

            printAll("keep successfully");
            dstatus = DONLINE;
            // 更新时间
            get_ctime(dUpdateAt, sizeof(dUpdateAt));
            sleep(10);
            continue;
        }
    }
    close(sock);
    return NULL;
}
