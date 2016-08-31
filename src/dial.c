#include "dial.h"
#include "public.h"
#include "dprotocol.h"
#include "xprotocol.h"


char index_html[] = "<!DOCTYPE html><html><head><meta http-equiv='refresh' content='%d'><meta charset='gbk'><style> body { width: 900px; margin: auto; font-family: 'Microsoft YaHei', '微软雅黑', Arial, Helvetica; } a{ text-decoration:none; } .code { font-family: 'consolas', monospace; } p { color: #333; margin: 3px 0; } p span { display: inline-block; vertical-align: top; } p .l { width: 30%%; margin-right: 5%%; } p .r { width: 65%%; } .inertia { font-size: 0.8rem; color: #aaa; margin-left: 5px; vertical-align: bottom; } h3 { display: inline-block; width: auto; font-size: 2rem; font-weight: bold; color: #34495e; margin: 20px 0; border-bottom: 5px solid #3498db; } h3 span { padding:0 10px; font-size: 1rem; font-weight: normal; color: #333; } .button { margin-top: 20px; background-color: #3498db; border-radius: 5px; float: right; color: #fff; padding: 10px 20px; cursor: pointer; } .button:hover { background-color: #2c7baf; }</style></head><body><a class='button' href='/logout'>登 出</a><h3>账户<span>Profile</span></h3><p><span class='l'>用户名<span class='inertia'>Username</span></span><span class='code r'>%s</span></p><p><span class='l'>网卡<span class='inertia'>Inet Face</span></span><span class='code r'>%s</span></p><p><span class='l'>端口地址<span class='inertia'>Host Ip</span></span><span class='code r'>%s</span></p><p><span class='l'>物理地址<span class='inertia'>Mac Addr</span></span><span class='code r'>%s</span></p><p><span class='l'>CPU 端模式<span class='inertia'>Cpu Endian</span></span><span class='code r'>%s</span><p/><h3>8021x 协议<span>8021x Protocol</span></h3><p><span class='l'>8021x 状态<span class='inertia'>8021x Status</span></span><span class='code r'>%s</span></p><p><span class='l'>8021x 通知<span class='inertia'>8021x Nodify</span></span><span class='r'>%s</span></p><p><span class='l'>最近更新<span class='inertia'>Update At</span></span><span class='code r'>%s</span></p><h3>DrCom 协议<span>DrCom Protocol</span></h3><p><span class='l'>DrCom 状态<span class='inertia'>DrCom Status</span></span><span class='code r'>%s</span></p><p><span class='l'>DrCom 日志<span class='inertia'>DrCom Log</span></span><span class='r'>%s</span></p><p><span class='l'>DrCom 消息<span class='inertia'>DrCom Message</span></span><span class='r'>%s</span></p><p><span class='l'>最近更新<span class='inertia'>Update At</span></span><span class='code r'>%s</span></p></body></html>";

char login_html[] = "<!DOCTYPE html><html><head><meta charset='gbk'><style> body { font-family: 'Microsoft YaHei', '微软雅黑', Arial, Helvetica; margin: auto; width: 256px; color: #333; } .theme { color: #3498db; } .dark-theme { color: #00025d; } form { margin: 100px 0; } .button { margin-top: 10px; background-color: #3498db; border-radius: 5px; color: #fff; padding: 10px 0; text-align: center; cursor: pointer; } .button:hover { background-color: #2c7baf; } .inputs { padding-top: 20px; background-color: rgba(0,0,0,.05); border-radius: 5px; } input[type='text'], input[type='password'] { box-sizing: border-box; padding: 10px 20px; width: 100%%; border: 0; outline: 0; background-color: transparent; } .title { font-weight: bold; font-size: 2rem; margin: 10px 0; }</style></head><body><form><div class='title'><span class='theme'>F</span><span class='dark-theme'>Scut</span><span class='theme'>Net</span></div><div class='inputs'><input type='text' placeholder='请输入账号...' id='userid'><input type='password' placeholder='请输入密码...' id='passwd' onkeydown='if(event.keyCode==13){login()}'></div><div class='button' onclick='login()'>登 录</div></form><script> function login(){ var userid = document.getElementById('userid').value; var passwd = document.getElementById('passwd').value; window.location = '/login?' + userid + ':' + passwd; }</script></body></html>";


int main()
{
    pthread_t xtid, dtid;

    /* user_id, passwd, interface_name: global var, defines in "public.h", char [32] */
    get_from_file(PASSWDFILE);
    // 登录状态清零
    is_login = 0;

    // init ip mac and socks
    init_dial_env();
    init_env_d();

    signal(SIGINT, sig_action);

    int ret;
    ret = pthread_create(&xtid, NULL, serve_forever_x, NULL);
    if( 0 != ret)
    {
        perror("Create 8021x thread failed");
        return ret;
    }

    ret = pthread_create(&dtid, NULL, serve_forever_d, NULL);
    if( 0 != ret)
    {
        perror("Create drcom thread failed");
        return ret;
    }

    // start http server
    http_server(NULL);

    pthread_join(dtid, NULL);
    pthread_join(xtid, NULL);
    return 0;
}


char* parseToOp(uint8_t *recv_buf, int len){
    static char op[128];
    // 先遍历到\r\n，然后再提取path
    for(int i=0; i<len - 1; ++i){
        if(recv_buf[i] == '\r' && recv_buf[i + 1] == '\n'){
            int l = 0, r = 0;
            while(l < len && recv_buf[l++] != '/');
            r = l;
            while(r < len && recv_buf[r] != ' ') ++r;
            // 防止溢出
            if(l >= len || r >= len || r-l > 128 - 1) return NULL;
            memcpy(op, recv_buf + l, r-l);
            op[r-l] = '\0';
            return op;
        }
    }
    return NULL;
}


void parseLoginInfo(char *op){
    int l = 0, r = 0;
    int len = strlen(op);

    while(l < len && op[l++] != '?');
    r = l;
    while(r < len && op[r] != ':') ++r;
    // 防止溢出
    if(l >= len || r >= len || r-l > 32 - 1 || len-r > 32 - 1){
        // 清空账号密码
        user_id[0] = 0;
        passwd[0] = 0;
        return;
    }
    memcpy(user_id, op + l, r-l);
    user_id[r-l] = '\0';

    ++r;
    memcpy(passwd, op + r, len-r);
    passwd[len-r] = '\0';
}


uint8_t* httpResponse(char* content){
    const char header[] = "HTTP/1.1 200 OK\r\nServer: fscutnet\r\nContent-Type: text/html;charset=gbk\r\nConnection: close\r\n\r\n";
    int len = strlen(header) + strlen(content) + 1;
    // 记得free
    char* buf = (char*) malloc(len);
    if(NULL == buf)
    {
        perror("Malloc for httpResponse failed");
        exit(-1);
    }
    strcpy(buf, header);
    strcat(buf, content);
    return (uint8_t*)buf;
}


uint8_t* httpRedirect(char* url){
    const char header[] = "HTTP/1.1 302 Moved Temporarily\r\nServer: fscutnet\r\nLocation:%s\r\nConnection: close\r\n\r\n";
    int len = strlen(header) + strlen(url) + 1;
    char* buf = (char*) malloc(len);
    if(NULL == buf)
    {
        perror("Malloc for httpRedirect failed");
        exit(-1);
    }
    sprintf(buf, header, url);
    return (uint8_t*)buf;
}


/* *************************************** 
*  recv msg from local host
*  use the msg to control dial routine
* ****************************************/
void *http_server(void *args)
{
    int listenfd, clientfd, nrecv, recv_err;
    uint8_t *recv_buf, *send_buf;
    char* op;

    struct sockaddr_in servaddr;
    struct sockaddr_in clntaddr;
    socklen_t addrlen = sizeof(clntaddr);

    recv_buf = malloc(ETH_DATA_LEN);
    if( recv_buf == NULL)
    {
        printf("Malloc for the recv_buf failed, in http_server function\n");
        exit(-1);
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(listen_port);
    inet_pton(AF_INET, listen_ip, &servaddr.sin_addr);

    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if( -1 == listenfd)
    {
        perror("Create listen socket failed");
        exit(-1);
    }

    // 绑定之前，设置其端口复用  
    int opt = 1;  
    if( 0 != setsockopt(listenfd, SOL_SOCKET,SO_REUSEADDR,   
        (const void *)&opt, sizeof(opt) ))
    {
        perror("listen socket REUSEADDR failed");
        exit(-1);
    }

    if( 0 != bind(listenfd, (struct sockaddr *) &servaddr, sizeof(servaddr)))
    {
        perror("Bind listenfd failed");
        exit(-1);
    }
    
    // set backlog
    listen(listenfd, 20);

    printf("Http server started on %s:%d\n", listen_ip, listen_port);
    while(1)
    {
        int len = 0;
        memset(recv_buf, 0, ETH_DATA_LEN);
        nrecv = 0;
        recv_err = 0;

        if ((clientfd = accept(listenfd, (struct sockaddr *)&clntaddr, &addrlen)) == -1) { 
            perror("http accept"); 
            continue; 
        }

        // 设置超时时间
        struct timeval ti;   
        ti.tv_sec = HTTP_TIMEOUT;
        ti.tv_usec = 0;
        setsockopt(clientfd, SOL_SOCKET, SO_RCVTIMEO, &ti, sizeof(ti));
        setsockopt(clientfd, SOL_SOCKET, SO_SNDTIMEO, &ti, sizeof(ti));

        do{
            len = recv(clientfd, recv_buf + nrecv, ETH_DATA_LEN - nrecv, 0);
            if(len <= 0){
                recv_err = 1; 
                break;
            }
            nrecv += len;
        } while((op = parseToOp(recv_buf, nrecv)) == NULL && nrecv < ETH_DATA_LEN);

        // printf("recv buf: %s\n", recv_buf);
        printf("http op: %s\n", op);

        if(recv_err){
            if(nrecv < 0)
               perror("http recv err");
            close(clientfd);
            continue;
        }

        if(op && strncmp(op, "login", 5) == 0 ){
            // 转换用户名和密码
            parseLoginInfo(op);
            is_login = 1;
            send_buf = httpRedirect("/");
        }
        else if(op && strncmp(op, "logout", 6) == 0 ){
            is_login = 0;
            logoff();
            send_buf = httpRedirect("/");
        }
        else{
            if(!is_login){
                send_buf = httpResponse(login_html);
            }
            else{
                char *cpuEndian;
                char *_8021xStatus;
                char *drcomStatus;
                // 页面自动刷新时间
                int refreshTime = 12;

                char* tempContent = (char*)malloc(2048 + strlen(index_html));
                if(NULL == tempContent)
                {
                    perror("Malloc for tempContent failed");
                    exit(-1);
                }

                if(checkCPULittleEndian()){
                    cpuEndian = "little";
                }
                else{
                    cpuEndian = "big";
                }

                if(xstatus == XOFFLINE){
                    _8021xStatus = "offline";
                    // 断线就多刷点
                    refreshTime = 1;
                }
                else if(xstatus == XONLINE){
                    _8021xStatus = "online";
                }
                else{
                    _8021xStatus = "error";
                }

                if(dstatus == DOFFLINE){
                    drcomStatus = "offline";
                    // 断线就多刷点
                    refreshTime = 1;
                }
                else if(dstatus == DONLINE){
                    drcomStatus = "online";
                }
                else{
                    drcomStatus = "error";
                }

                sprintf(tempContent, index_html, refreshTime, user_id, interface_name, inet_ntoa(my_ip.sin_addr), mac_ntoa(my_mac), cpuEndian,
                    _8021xStatus, nodifyMsg, xUpdateAt, drcomStatus, dstatusMsg, dsystemMsg, dUpdateAt);

                send_buf = httpResponse(tempContent);
                free(tempContent);
            }
        }

        int send_len = send(clientfd, send_buf, strlen(send_buf), 0);
        if(send_len != strlen(send_buf)){
            printf("http response send error\n");
        }
        free(send_buf);
        close(clientfd);
    }
}


void sig_action(int signo)
{
    if( SIGINT == signo)
    {
        logoff();
        printf("Logging off, and exit.\n");
        // printf("Logging off, please waitting 5sec\n");
        // sleep(5);
        exit(0);
    }
}
