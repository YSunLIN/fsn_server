#include "public.h"
#include <stdlib.h>
#include <string.h>

void print_mac(char *src)
{
    char mac[32] = ""; 
    sprintf(mac, "%02x%02x%02x%02x%02x%02x",
                        (unsigned char)src[0],
                        (unsigned char)src[1],
                        (unsigned char)src[2],
                        (unsigned char)src[3],
                        (unsigned char)src[4],
                        (unsigned char)src[5]);

    printf("%s\n", mac);
}


char* mac_ntoa(char src[ETH_ALEN])
{
    static char mac_str[32] = ""; 
    sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
                        (unsigned char)src[0],
                        (unsigned char)src[1],
                        (unsigned char)src[2],
                        (unsigned char)src[3],
                        (unsigned char)src[4],
                        (unsigned char)src[5]);

    return mac_str;
}


void print_hex(char *hex, int len)
{
    int i;
    for(i=0; i<len; ++i)
        printf("%02x ", (unsigned char)hex[i]);
    printf("\n");
}


inline int checkCPULittleEndian()
{
    union
    {
        unsigned int a;
        unsigned char b;
    } c;
    c.a = 1;
    return (c.b == 1);
}


inline uint32_t big2little_32(uint32_t A)
{
    return ((((uint32_t)(A) & 0xff000000) >>24) | 
        (((uint32_t)(A) & 0x00ff0000) >> 8) | 
        (((uint32_t)(A) & 0x0000ff00) << 8) | 
        (((uint32_t)(A) & 0x000000ff) << 24));
}


/* ************************************************************************ 
      get the user information and listen ip from the file
      interface_name which will be used in crt_sock()
* ************************************************************************/
void str_strip(char *str){
    char *ptmp = str;
    while(*ptmp != '\n' && *ptmp != '\r' && *ptmp != '\0' && *ptmp != ' '  && *ptmp != '\t')
        ptmp++;
    *ptmp = '\0';
}

#ifdef NO_UCI
void get_from_file(char *filename)
{
    FILE *fp;
    static char temp[32]  = {0};

    fp = fopen(filename, "r");
    if( NULL == fp)
    {
        printf("Please check the %s does exist!\n", filename);
        exit(-1);
    }

    fgets(user_id, 31, fp);
    str_strip(user_id);
    if(strlen(user_id) == 0){
        printf("Username not exists in %s\n", filename);
        exit(-1);
    }

    fgets(passwd, 31, fp);
    str_strip(passwd);
    if(strlen(passwd) == 0){
        printf("Password not exists in %s\n", filename);
        exit(-1);
    }

    fgets(interface_name, 31, fp);
    str_strip(interface_name);
    if(strlen(interface_name) == 0){
        printf("Internet face not exists in %s\n", filename);
        exit(-1);
    }
    
    fgets(listen_ip, 31, fp);
    str_strip(listen_ip);
    if(strlen(listen_ip) == 0){
        printf("Listen IP:Port not exists in %s\n", filename);
        exit(-1);
    }

    char* tmp_p = listen_ip;
    while(*tmp_p && *tmp_p != ':') tmp_p++;
    if(*tmp_p == '\0'){
        printf("Listen IP:Port format error in %s\n", filename);
        exit(-1);
    }

    *tmp_p = '\0';
    str_strip(listen_ip);
    listen_port = atoi(tmp_p + 1);

    fclose(fp);
    // printf("%s %s %s\n", user_id, passwd, interface_name);
}

#else
void runCommand(char buf[], int len, const char *command)
{
    FILE *stream;
    stream = popen(command, "r");
    if(stream == NULL){
        fprintf(stderr, "run command error : %s\n", command);
    }
    else{
        fread(buf, sizeof(char), len, stream); 
    }
    str_strip(buf);
}

void get_from_file(char *filename)
{
    FILE *fp;
    static char temp[32]  = {0};

    fp = fopen(filename, "r");
    if( NULL == fp)
    {
        // 清空账号密码
        user_id[0] = 0;
        passwd[0] = 0;
    }
    else
    {
        fgets(user_id, 31, fp);
        str_strip(user_id);
        if(strlen(user_id) == 0){
            printf("Username not exists in %s\n", filename);
            exit(-1);
        }

        fgets(passwd, 31, fp);
        str_strip(passwd);
        if(strlen(passwd) == 0){
            printf("Password not exists in %s\n", filename);
            exit(-1);
        }
        fclose(fp);
    }

    runCommand(interface_name, 32, "uci get network.wan.ifname");
    runCommand(listen_ip, 32, "uci get network.lan.ipaddr");
    listen_port = 7288;
}
#endif


void save_to_file(char* filename)
{
    FILE *fp;
    static char temp[32]  = {0};

    fp = fopen(filename, "w");
    if(NULL == fp)
    {
        printf("Please check the permission to write %s!\n", filename);
        return;
    }

    // 写账号
    strcpy(temp, user_id);
    strcat(temp, "\r\n");
    fwrite (temp, 1, strlen(temp), fp);

    // 写密码
    strcpy(temp, passwd);
    strcat(temp, "\r\n");
    fwrite (temp, 1, strlen(temp), fp);

    // 写接口名
    strcpy(temp, interface_name);
    strcat(temp, "\r\n");
    fwrite (temp, 1, strlen(temp), fp);

    // 写局域网监听地址
    sprintf(temp, "%s:%d\r\n", listen_ip, listen_port);
    fwrite (temp, 1, strlen(temp), fp);
    fclose(fp);
}


// 非线程安全
void get_ctime(char* buf, int len){
    time_t time_raw_format;  
    struct tm * time_struct;

    time ( &time_raw_format );  
    // localtime : time_t -> tm 此函数返回的时间日期经时区转换 
    time_struct = localtime ( &time_raw_format );
    strftime (buf, len, "%F %T %Z", time_struct);
}


// 非线程安全
int is_forbid_time(){
    // time_t time_raw_format;  
    // struct tm * time_struct;
    // int tm_hour, tm_wday;

    // time ( &time_raw_format );  
    // // localtime : time_t -> tm 此函数返回的时间日期经时区转换 
    // time_struct = localtime ( &time_raw_format );
    
    // tm_hour = time_struct->tm_hour;
    // tm_wday = time_struct->tm_wday;

    // // 周一到周五的 0点到6点
    // if(tm_hour >= 0 && tm_hour < 6 &&
    //     tm_wday >= 1 && tm_wday <= 5){
    //     return 1;
    // }
    // return 0;
    return is_stop_auth;
}
