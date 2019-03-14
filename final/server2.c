#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

typedef struct{
    char *ip;
    unsigned short port;
} Userdata;

Userdata userdata[1024];


// 取得 sockaddr，IPv4 或 IPv6：

int main(int argc, char *argv[]){
    fd_set master; // master file descriptor 清單
    fd_set read_fds; // 給 select() 用的暫時 file descriptor 清單
    int fdmax; // 最大的 file descriptor 數目

    int listener; // listening socket descriptor
    int newfd; // 新接受的 accept() socket descriptor
    struct sockaddr_in remoteaddr; // client address
    socklen_t addrlen;

    char buf[256]; // 儲存 client 資料的緩衝區
    int nbytes;

    char remoteIP[INET6_ADDRSTRLEN];

    int yes = 1; // 供底下的 setsockopt() 設定 SO_REUSEADDR
    int i, j, rv;

    struct addrinfo hints, *ai, *p;

    FD_ZERO(&master); // 清除 master 與 temp sets
    FD_ZERO(&read_fds);

    // 給我們一個 socket，並且 bind 它
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if((rv = getaddrinfo(NULL, argv[1], &hints, &ai)) != 0) {
        fprintf(stderr, "selectserver: %s\n", gai_strerror(rv));
        exit(1);
    }

    for(p = ai; p != NULL; p = p->ai_next){
        listener = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (listener < 0) {
            continue;
        }

        // 避開這個錯誤訊息："address already in use"
        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

        if (bind(listener, p->ai_addr, p->ai_addrlen) < 0) {
            close(listener);
            continue;
        }

        break;
    }

    // 若我們進入這個判斷式，則表示我們 bind() 失敗
    if (p == NULL){
        fprintf(stderr, "selectserver: failed to bind\n");
        exit(2);
    }
    freeaddrinfo(ai); // all done with this

    // listen
    if (listen(listener, 100) == -1) {
        perror("listen");
        exit(3);
    }

    // 將 listener 新增到 master set
    FD_SET(listener, &master);

    // 持續追蹤最大的 file descriptor
    fdmax = listener; // 到此為止，就是它了

    // 主要迴圈
    while(1){
        read_fds = master; // 複製 master
        int rt;
        if ((rt = select(fdmax+1, &read_fds, NULL, NULL, NULL)) == -1) {
            perror("select");
            exit(4);
        }
        else if(rt != 0){
            for(i = 3; i < FD_SETSIZE; i++){
                if (FD_ISSET(i, &read_fds)){ // 我們找到一個！！
                    if (i == listener){
                        // handle new connections
                        addrlen = sizeof(remoteaddr);
                        newfd = accept(listener, (struct sockaddr *)&remoteaddr, &addrlen);
                        userdata[newfd].ip = inet_ntoa(remoteaddr.sin_addr);
                        userdata[newfd].port = remoteaddr.sin_port;
                        if (newfd == -1){
                            perror("accept");
                        }
                        else{
                            FD_SET(newfd, &master); // 新增到 master set
                            if(newfd > fdmax) { // 持續追蹤最大的 fd
                                fdmax = newfd;
                            }
                        }
                    } 
                    else if ((nbytes = recv(i, buf, sizeof(buf), 0)) <= 0){
                        // got error or connection closed by client
                        close(i);
                        FD_CLR(i, &master); // 從 master set 中移除
                        continue;
                    }
                    else if(nbytes > 0){
                        //printf("%d\n", nbytes);
                        //for(int k = 0; k < nbytes; k++) printf(k != nbytes - 1 ? "%d ":"%d\n", (int)buf[k]);
                        //puts(buf);
                        printf("recv from %s:%d\n", userdata[i].ip, (int)userdata[i].port);
                        //sleep(1);
                        send(i, buf, nbytes, 0);
                    }
                } // END got new incoming connection
            } // END looping through file descriptors
        }
        sleep(1);
    } // END for( ; ; )--and you thought it would never end!

    return 0;
}