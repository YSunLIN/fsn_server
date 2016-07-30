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
    while(*ptmp != '\n' && *ptmp != '\0' && *ptmp != ' '  && *ptmp != '\t')
        ptmp++;
    *ptmp = '\0';
}

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
