#include "dial.h"

int main()
{
	pthread_t xtid, dtid;

	/* user_id, passwd, interface_name: global var, defines in "public.h", char [32] */
    get_from_file(PASSWDFILE);

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
	char* pbuf;
	for(int i=0; i<len - 1; ++i){
		if(recv_buf[i] == '\r' && recv_buf[i + 1] == '\n'){
			int l = 0, r = 0;
			while(l < len && recv_buf[l++] != '/');
			r = l;
			while(r < len &&recv_buf[r] != ' ') ++r;
			if(l >= len || r >= len) return NULL;
			memcpy(op, recv_buf + l, r-l);
			op[r-l] = '\0';
			return op;
		}
	}
	return NULL;
}


uint8_t* httpResponse(char* content){
	static char buf[4096];
	const char header[] = "HTTP/1.1 200 OK\r\nServer: fscutnet\r\nContent-Type: text/html;charset=utf-8\r\n\r\n";
	strcpy(buf, header);
	strcat(buf, content);
	return (uint8_t*)buf;
}


uint8_t* httpRedirect(char* url){
    static char buf[4096];
    const char header[] = "HTTP/1.1 302 Moved Temporarily\r\nServer: fscutnet\r\nLocation:%s\r\n\r\n";
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

        if(op && strcmp(op, "on") == 0 ){
			logon();
            send_buf = httpRedirect("/");
        }
        else if(op && strcmp(op, "off") == 0 ){
        	logoff();
            send_buf = httpRedirect("/");
        }
        else{
        	char* tempContent = (char*)malloc(2048);
            memset(tempContent, 0, 2048);

            strcat(tempContent, "<h3>Profile</h3>");
            strcat(tempContent, "username: ");
            strcat(tempContent, user_id);
            strcat(tempContent, "<br/>");

            strcat(tempContent, "inet face: ");
            strcat(tempContent, interface_name);
            strcat(tempContent, "<br/>");

            strcat(tempContent, "host ip: ");
            strcat(tempContent, inet_ntoa(my_ip.sin_addr));
            strcat(tempContent, "<br/>");

            strcat(tempContent, "cpu endian: ");
            if(checkCPULittleEndian())
                strcat(tempContent, "little");
            else
                strcat(tempContent, "big");
            strcat(tempContent, "<br/>");

            strcat(tempContent, "<a href='/on'>login</a>");
            strcat(tempContent, "&nbsp;&nbsp;&nbsp;&nbsp;");
            strcat(tempContent, "<a href='/off'>logout</a>");
            strcat(tempContent, "<br/>");

            strcat(tempContent, "<br/><h3>8021x protocol</h3>");
            if(xstatus == XOFFLINE){
                strcat(tempContent, "8021x status: offline<br/>");
                strcat(tempContent, "8021x nodify: ");
                strcat(tempContent, nodifyMsg);
                strcat(tempContent, "<br/>");
            }
            else if(xstatus == XONLINE)
                strcat(tempContent, "8021x status: online<br/>");
            else{
                strcat(tempContent, "8021x status: error<br/>");
                strcat(tempContent, "8021x nodify: ");
                strcat(tempContent, nodifyMsg);
                strcat(tempContent, "<br/>");
            }

            strcat(tempContent, "<br/><h3>DrCOM protocol</h3>");
            if(dstatus == DOFFLINE){
                strcat(tempContent, "drcom status: offline<br/>");
                strcat(tempContent, "drcom msg: ");
                strcat(tempContent, dstatusMsg);
                strcat(tempContent, "<br/>");
            }
            else if(dstatus == DONLINE)
                strcat(tempContent, "drcom status: online<br/>");
            else{
                strcat(tempContent, "drcom status: error<br/>");
                strcat(tempContent, "drcom msg: ");
                strcat(tempContent, dstatusMsg);
                strcat(tempContent, "<br/>");
            }

            send_buf = httpResponse(tempContent);
            free(tempContent);
        }

        int send_len = send(clientfd, send_buf, strlen(send_buf), 0);
        if(send_len != strlen(send_buf)){
        	printf("http response send error\n");
        }
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
