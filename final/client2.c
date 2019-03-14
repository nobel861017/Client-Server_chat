#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <pthread.h>

#include "common.h"
#include "client.h"

typedef struct {
	char host[20];
	int port;
}Pair;

int n = 0, t = 1000, pair_idx = 0;

Pair pair[1000];

struct timeval timev;

void parse_args(int argc , char *argv[]){
	for(int i = 1; i < argc; i++){
        for(int j = 0; ; j++){
            if(argv[i][j] == ':'){
                strncpy(pair[pair_idx].host, argv[i], j);
                char tmp[200];
                strncpy(tmp, &argv[i][j+1], strlen(argv[i]) - j);
                pair[pair_idx].port = atoi(tmp);
                fprintf(stderr, "host:%s, port:%d\n", pair[pair_idx].host, pair[pair_idx].port);
                break;
            }
        }
        pair_idx ++;
    }
}

static int login(line_client* client) {
    line_protocol_login req;
    memset(&req, 0, sizeof(req));
    req.message.header.req.magic = LINE_PROTOCOL_MAGIC_REQ;
    req.message.header.req.op = LINE_PROTOCOL_OP_LOGIN;
    req.message.header.req.datalen = sizeof(req) - sizeof(req.message.header);
    memcpy(req.message.body.user, client->arg.user, strlen(client->arg.user));
    md5(client->arg.passwd, strlen(client->arg.passwd), req.message.body.passwd_hash);
    if (!send_message(client->conn_fd, &req, sizeof(req))) {
        fprintf(stderr, "send fail\n");
        return 0;
    }
    line_protocol_header header;
    memset(&header, 0, sizeof(header));
    if (recv_message(client->conn_fd, &header, sizeof(header))) {
        if (header.res.magic == LINE_PROTOCOL_MAGIC_RES &&
            header.res.op == LINE_PROTOCOL_OP_LOGIN &&
            header.res.status == LINE_PROTOCOL_STATUS_OK) {
            client->client_id = header.res.client_id;
            return 1;
        } else {
            return 0;
        }
    }
    return 0;
}

void type_command(){
    char cmd[2];
    puts("Please insert command");
    scanf("%s", cmd);

}

int init(){
    //socket的建立
    int sockfd = 0;
    sockfd = socket(AF_INET , SOCK_STREAM , 0);

    if (sockfd == -1){
        printf("Fail to create a socket.");
    }

    //socket的連線

    struct sockaddr_in info;
    bzero(&info,sizeof(info));
    info.sin_family = AF_INET;

    //localhost test
    info.sin_addr.s_addr = inet_addr(pair[0].host);
    info.sin_port = htons(pair[0].port);


    int err = connect(sockfd,(struct sockaddr *)&info,sizeof(info));
    if(err == -1){
        printf("timeout when connect to %s\n", pair[0].host);
    }
    return sockfd;
}

void ping_server(int sockfd){
    char buf[256] = "ping\0";
	char rec_buf[1000];
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timev, sizeof(timev));
    clock_t begin = clock();
    send(sockfd, buf, strlen(buf), 0);
    int rt = recv(sockfd, rec_buf, sizeof(rec_buf), 0);
    sleep(1);
    if(rt == -1){
        printf("timeout when connect to %s\n", pair[0].host);
    }
    clock_t end = clock();
    double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;

    printf("recv from %s, RTT = %lf msec\n", pair[0].host, time_spent*1000);
}

int main(int argc , char *argv[]){
    //ios_base::sync_with_stdio(false);
	//cin.tie(0);

	parse_args(argc, argv);

    int sockfd = init();

    //Send a message to server
    while(1){
        ping_server(sockfd);
        type_command();
    }

    close(sockfd);
    
    return 0;
}














