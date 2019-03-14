#include "server.h"

#include "common.h"
#include "connect.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <fcntl.h>

static int parse_arg(line_server* server, int argc, char** argv);
static void *handle_request(void *void_thread_args);
static int get_account_info(line_server* server,  const char* user, line_account_info* info);
static void login(line_server* server, int conn_fd, line_protocol_login* login);
static void logout(line_server* server, int conn_fd);
static char* get_user_homedir(line_server* server, line_client_info* info);
static int sync_match_to_server(line_protocol_match req, int conn_fd, line_server *server);
static void sync_unmatch_to_server(line_protocol_match req, int conn_fd, line_server *server);
static int find_matching_client(char *name);
static int send_meta_to_client(line_protocol_msg_file *req, line_client_info **client, char *sender, int recv_res_fd);
static int find_online_user_fd(line_client_info **client, char *user);
static void find_unread_message(char *filename, message_container *container);
static int send_logout_res_to_client(line_protocol_match req, int conn_fd, line_server *server);


static int sync_meta_in_server(line_protocol_msg_file *req, int conn_fd, line_server *server){
    line_protocol_header response;
    memset(&response,0,sizeof(response));
    response.req.magic = LINE_PROTOCOL_MAGIC_RES;
    response.res.op = LINE_PROTOCOL_OP_SYNC_META;
    response.res.datalen = 0;
    response.res.status = LINE_PROTOCOL_STATUS_OK;

    if(req->message.body.is_msg == 1){
        // handle sending messages
        char talk_filename[FILE_NAME_MAX];
        sprintf(talk_filename, "../sdir/%s/talk_%s.csv", server->client[conn_fd]->account.user, req->message.body.recv_user);
        time_t t;
        t = time(NULL);
        FILE *fp = fopen(talk_filename, "a");
        fprintf(fp, "%d,0,%d,%s\n", req->message.body.is_msg, t, req->message.body.data);
        fclose(fp);
    }else if(req->message.body.is_msg == 0){
        // handle sending file
        int fd;
        char save_filename[FILE_NAME_MAX];
        sprintf(save_filename, "../sdir/%s/%s", server->client[conn_fd]->account.user, req->message.body.filename);
        /*struct stat stat;
        if(lstat(save_filename, &stat) >= 0){
            unlink(save_filename);
        }*/
        if(req->message.body.first)
            fd = open(save_filename,O_WRONLY | O_CREAT | O_TRUNC, REG_S_FLAG);
        else
            fd = open(save_filename,O_WRONLY | O_CREAT | O_APPEND, REG_S_FLAG);
        write(fd, req->message.body.data, req->message.body.data_len);
        //if(req->message.body.finished)
        close(fd);
        fprintf(stderr, "Write data to file: %s\n", save_filename);
        if(req->message.body.finished == 1){
            fprintf(stderr,"got last fragment of file %s\n", req->message.body.filename);
            char talk_filename[FILE_NAME_MAX];
            sprintf(talk_filename, "../sdir/%s/talk_%s.csv", server->client[conn_fd]->account.user, req->message.body.recv_user);
            time_t t;
            t = time(NULL);
            FILE *fp = fopen(talk_filename, "a");
            fprintf(fp, "%d,0,%d,%s\n", req->message.body.is_msg, t, req->message.body.filename);
            fclose(fp);
        }
    }else{
        fprintf(stderr, "Option set to LINE_PROTOCOL_OP_SYNC_META but receive is_msg to be not 0 or 1.");
        response.res.status = LINE_PROTOCOL_STATUS_FAIL;
        send_message(conn_fd, &response, sizeof(response));
        return -1;
    }
    // send response OK
    fprintf(stderr, "Server send respose to client A with status code %d.\n", response.res.status);
    return send_message(conn_fd, &response, sizeof(response));
}

static int sync_meta_in_server_log(line_protocol_msg_file *req, int conn_fd, line_server *server){
    fprintf(stderr, "sync_meta_in_server_log\n");
    line_protocol_header response;
    memset(&response,0,sizeof(response));
    response.req.magic = LINE_PROTOCOL_MAGIC_RES;
    response.res.op = LINE_PROTOCOL_OP_LOG;
    response.res.datalen = 0;
    response.res.status = LINE_PROTOCOL_STATUS_OK;

    return send_message(conn_fd, &response, sizeof(response));
}

static int sync_meta_in_server_add_friend(line_protocol_msg_file *req, int conn_fd, line_server *server){
    line_protocol_header response;
    memset(&response,0,sizeof(response));
    response.req.magic = LINE_PROTOCOL_MAGIC_RES;
    response.res.op = LINE_PROTOCOL_OP_SYNC_META;
    response.res.datalen = 0;
    response.res.status = LINE_PROTOCOL_STATUS_OK;
    return send_message(conn_fd, &response, sizeof(response));
}

int cmp(const void *a, const void *b){
    return strcmp(((message_buf*)a)->time, ((message_buf*)b)->time);
}

static int log_data(char *data, char *sender, char *recv_user){
    fprintf(stderr, "log data\n");
    char path1[FILE_NAME_MAX], path2[FILE_NAME_MAX], buf_tmp[MESSAGE_LEN_MAX];
    message_buf buf[2000];
    int finish1 = 0, finish2 = 0, num = 0;
    memset(buf_tmp, 0, sizeof(buf_tmp));
    memset(path1, 0, sizeof(path1));
    memset(path2, 0, sizeof(path2));
    //memset(buf1, 0, sizeof(buf1));
    //memset(buf2, 0, sizeof(buf2));
    sprintf(path1, "../sdir/%s/talk_%s.csv", sender, recv_user);
    sprintf(path2, "../sdir/%s/talk_%s.csv", recv_user, sender);
    FILE *fp1 = fopen(path1, "r");
    FILE *fp2 = fopen(path2, "r");
    while(fgets(buf_tmp, MESSAGE_LEN_MAX, fp1) != NULL){
        
        buf[num].Is_sender = 1;
        for(int i = 0; i < 10; i++){
            buf[num].time[i] = buf_tmp[i+4];
        }
        buf[num].time[11] = '\0';
        if(buf_tmp[0] == '1'){
            buf[num].Is_msg = 1;
            // Caesar Cypher Algorithm Decryption
            for(int i = 15; (i < MESSAGE_LEN_MAX && buf_tmp[i] != '\n'); i++)
                buf_tmp[i] = buf_tmp[i] - 3;
        }
        else{
            buf[num].Is_msg = 0;
        }
        strcpy(buf[num].message, &buf_tmp[4]);
        memset(buf_tmp, 0, sizeof(buf_tmp));
        num ++;
    }
    fclose(fp1);
    while(fgets(buf_tmp, MESSAGE_LEN_MAX, fp2) != NULL){
        
        buf[num].Is_sender = 0;
        for(int i = 0; i < 10; i++){
            buf[num].time[i] = buf_tmp[i+4];
        }
        buf[num].time[11] = '\0';
        if(buf_tmp[0] == '1'){
            buf[num].Is_msg = 1;
            // Caesar Cypher Algorithm Decryption
            for(int i = 15; (i < MESSAGE_LEN_MAX && buf_tmp[i] != '\n'); i++)
                buf_tmp[i] = buf_tmp[i] - 3;
        }
        else{
            buf[num].Is_msg = 0;
        }
        strcpy(buf[num].message, &buf_tmp[4]);
        memset(buf_tmp, 0, sizeof(buf_tmp));
        num ++;
    }
    fclose(fp2);
    //fprintf(stderr, "num = %d\n", num);
    
    qsort(buf, num, sizeof(message_buf), cmp);
    /*for(int i = 0; i < num; i++){
        fprintf(stderr, "Is_sender = %d, %s", buf[i].Is_sender, buf[i].message);
    }*/
    
    char log_path[FILE_NAME_MAX];//, data_buf[MESSAGE_LEN_MAX];
    memset(log_path, 0, sizeof(log_path));
    sprintf(log_path, "../sdir/%s/log", sender);
    FILE *fp = fopen(log_path, "w+");
    for(int i = 0; i < num; i++){
        //memset(data_buf, 0, sizeof(data_buf));
        if(buf[i].Is_sender == 1){
            if(buf[i].Is_msg == 1){
                //fprintf(stderr, "%s: %s", sender, &buf[i].message[11]);
                fprintf(fp, "%s: %s", sender, &buf[i].message[11]);
            }
            else{
                //fprintf(stderr, "%s send file: %s", sender, &buf[i].message[11]);
                fprintf(fp, "%s send file: %s", sender, &buf[i].message[11]);
            }
        }
        else if(buf[i].Is_sender == 0){
            if(buf[i].Is_msg == 1){
                //fprintf(stderr, "%s: %s", recv_user, &buf[i].message[11]);
                fprintf(fp, "%s: %s", recv_user, &buf[i].message[11]);
            }
            else{
                //fprintf(stderr, "%s send file: %s", recv_user, &buf[i].message[11]);
                fprintf(fp, "%s send file: %s", recv_user, &buf[i].message[11]);
            }
        }
    }
    fclose(fp);
    memset(data, 0, sizeof(data));
    int fd = open(log_path, O_RDONLY);
    int datalen = read(fd, data, DATA_LEN_MAX);
    close(fd);
    fprintf(stderr, "datelen = %d\n", datalen);
    return datalen;
}

static int send_log_meta_to_client(line_protocol_msg_file *req, int conn_fd, line_client_info **client, char *sender, int recv_res_fd){
    int send_fd = conn_fd;
    int ret = 0;
    line_protocol_msg_file to_client_req;
    memset(&to_client_req, 0, sizeof(to_client_req));
    to_client_req.message.header.req.magic = LINE_PROTOCOL_MAGIC_REQ;
    to_client_req.message.header.req.op = LINE_PROTOCOL_OP_LOG;
    to_client_req.message.header.req.datalen = sizeof(to_client_req) - sizeof(to_client_req.message.header);
    char buf[FILE_LEN_MAX];
    int log_data_len = log_data(buf, req->message.body.sender, req->message.body.recv_user);
    ret = send_log_to_client(
            send_fd, 
            recv_res_fd, 
            buf, 
            log_data_len, 
            sender, 
            &to_client_req);
    if(ret == -1){
        fprintf(stderr, "Error: Server send file to client error\n");
    }
    fprintf(stderr, "Server finished sending log file\n");
}

static int send_add_friend_to_client(line_protocol_msg_file *req, line_client_info **client, char *sender, int recv_res_fd){
    int send_fd = find_online_user_fd(client, req->message.body.recv_user);
    int ret = 0;
    if(send_fd == -1){
        fprintf(stderr, "User %s not online\n", req->message.body.recv_user);
    }else if(strncmp(client[send_fd]->match_username, sender, USER_LEN_MAX) != 0){
        fprintf(stderr, "User online but not matched to sender.\n");
    }else{
        line_protocol_msg_file to_client_req;
        memset(&to_client_req, 0, sizeof(to_client_req));
        to_client_req.message.header.req.magic = LINE_PROTOCOL_MAGIC_REQ;
        to_client_req.message.header.req.op = LINE_PROTOCOL_OP_ADD_FRIEND;
        to_client_req.message.header.req.datalen = sizeof(to_client_req) - sizeof(to_client_req.message.header);
        ret = send_add_friend_req_to_server_or_client(
            send_fd, 
            recv_res_fd, 
            req->message.body.sender,
            req->message.body.recv_user, 
            &to_client_req);
    }
    free(req);
    return ret;
}

static int send_meta_to_client(line_protocol_msg_file *req, line_client_info **client, char *sender, int recv_res_fd){
    int send_fd = find_online_user_fd(client, req->message.body.recv_user);
    int ret = 0;
    //fprintf(stderr, "is_msg == %d\n", req->message.body.is_msg);
    if(send_fd == -1){
        fprintf(stderr, "User %s not online\n", req->message.body.recv_user);
    }else if(strncmp(client[send_fd]->match_username, sender, USER_LEN_MAX) != 0){
        fprintf(stderr, "User online but not matched to sender.\n");
    }else{
        if(req->message.body.is_msg == 1){
            fprintf(stderr, "Server starts sending message from %s to %s\n", sender, req->message.body.recv_user);
            message_container unread_message;
            char talk_filename[FILE_NAME_MAX];
            sprintf(talk_filename, "../sdir/%s/talk_%s.csv", sender, req->message.body.recv_user);
            find_unread_message(talk_filename, &unread_message);
            //fprintf(stderr, "we are still here!\n");
            line_protocol_msg_file to_client_req;
            memset(&to_client_req, 0, sizeof(to_client_req));
            to_client_req.message.header.req.magic = LINE_PROTOCOL_MAGIC_REQ;
            to_client_req.message.header.req.op = LINE_PROTOCOL_OP_SYNC_META;
            to_client_req.message.header.req.datalen = sizeof(to_client_req) - sizeof(to_client_req.message.header);
            for(int msg_i = 0; msg_i < unread_message.total_message; msg_i ++){
                fprintf(stderr, "%s\n", unread_message.message[msg_i]);
            }
            for(int msg_i = 0; msg_i < unread_message.total_message; msg_i ++){
                ret = send_message_to_server_or_client(
                        send_fd, 
                        recv_res_fd, 
                        unread_message.message[msg_i], 
                        strlen(unread_message.message[msg_i]) + 1, 
                        req->message.body.recv_user, 
                        &to_client_req);
                if(ret == -1){
                    fprintf(stderr, "Error: Server send unread message to client error\n");
                    break;
                }
            }
            fprintf(stderr, "Server finished sending message\n");
        }
        else if(req->message.body.is_msg == 0){
            // send file to client B
            fprintf(stderr, "Server starts sending file from %s to %s\n", sender, req->message.body.recv_user);
            /*char buf[4096], filename[FILE_NAME_MAX];
            sprintf(filename, "../sdir/%s/%s", sender, req->message.body.filename);
            int fd = open(filename, O_RDONLY);
            int datalen = read(fd,buf,sizeof(buf));
            close(fd);*/
            int fd;
            if(req->message.body.first){
                fd = open(req->message.body.filename, O_WRONLY | O_CREAT | O_TRUNC, REG_S_FLAG);
            }
            write(fd, req->message.body.data, req->message.body.data_len);
            if(req->message.body.finished) close(fd);
            
            line_protocol_msg_file to_client_req;
            memset(&to_client_req, 0, sizeof(to_client_req));
            to_client_req.message.header.req.magic = LINE_PROTOCOL_MAGIC_REQ;
            to_client_req.message.header.req.op = LINE_PROTOCOL_OP_SYNC_META;
            to_client_req.message.header.req.datalen = sizeof(to_client_req) - sizeof(to_client_req.message.header);
            ret = send_file_to_server_or_client(
                    send_fd, 
                    recv_res_fd, 
                    req->message.body.data, 
                    req->message.body.data_len, 
                    req->message.body.recv_user, 
                    &to_client_req,
                    req->message.body.first, 
                    req->message.body.finished,
                    req->message.body.filename);
            if(ret == -1){
                fprintf(stderr, "Error: Server send file to client error\n");
            }
            fprintf(stderr, "Server finished sending file\n");
        }
    }
    free(req);
    return ret;
}

static void find_unread_message(char *filename, message_container *container){
    fprintf(stderr, "%s\n", filename);
    FILE *fp = fopen(filename, "r");
    container->total_message = 0;
    char buf[DATA_LEN_MAX];
    int first_print = 1;
    fprintf(stderr, "unread messages:\n");
    while(fgets(buf, DATA_LEN_MAX, fp) != NULL){
        if(strncmp(buf, "\n", DATA_LEN_MAX) == 0)
            continue;
        if(buf[2] == '0'){
            buf[strlen(buf)-1] = '\0';
            fprintf(stderr, "%s\n", buf);
            strncpy(container->message[container->total_message], buf, DATA_LEN_MAX);
            container->total_message ++;
        }
    }
    fprintf(stderr, "--------------------\n", buf);
    fclose(fp);
    fp = fopen(filename, "r");
    FILE *fp2 = fopen("tmp", "w");
    while(fgets(buf, DATA_LEN_MAX, fp) != NULL){
        if(strncmp(buf, "\n", DATA_LEN_MAX) == 0)
            continue;
        buf[2] = '1';
        fprintf(fp2, "%s", buf);
    }
    fclose(fp);
    fclose(fp2);
    rename("tmp", filename);
}

static int find_online_user_fd(line_client_info **client, char *user){
    for(int fd = 0; fd < getdtablesize(); fd++){
        if(client[fd] != NULL){
            if(strncmp(client[fd]->account.user, user, USER_LEN_MAX) == 0){
                return client[fd]->conn_fd;
            }
        }
    }
    return -1;
}

//read config file, and start to listen
void line_server_init(
    line_server** server, int argc, char** argv) {
    line_server* tmp = (line_server*)malloc(sizeof(line_server));
    if (!tmp) {
        fprintf(stderr, "server malloc fail\n");
        return;
    }
    memset(tmp, 0, sizeof(line_server));
    if (!parse_arg(tmp, argc, argv)) {
        fprintf(stderr, "Usage: %s [config file]\n", argv[0]);
        free(tmp);
        return;
    }
    int fd = server_start();
    if (fd < 0) {
        fprintf(stderr, "server fail\n");
        free(tmp);
        return;
    }
    tmp->client = (line_client_info**)
    malloc(sizeof(line_client_info*) * getdtablesize());
    if (!tmp->client) {
        fprintf(stderr, "client list malloc fail\n");
        close(fd);
        free(tmp);
        return;
    }
    memset(tmp->client, 0, sizeof(line_client_info*) * getdtablesize());
    tmp->listen_fd = fd;
    *server = tmp;
}

//wait client to connect and handle requests from connected socket fd
int line_server_run(line_server* server) {
    fd_set master; FD_ZERO(&master);
    fd_set read_fds; FD_ZERO(&read_fds);
    FD_SET(server->listen_fd, &master);
    int fd_max = server->listen_fd;
    pthread_t **t;
    t = (pthread_t **) malloc(sizeof(pthread_t *) * MAX_CLIENT);

    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(server->listen_fd, &read_fds);
        fprintf(stderr, "Server main thread listening fd:%d\n", server->listen_fd);
        //read_fds will be modified after select
        if( select(fd_max+1, &read_fds, NULL, NULL, NULL) == -1 ) {
            perror("select for main thread");
        }
        //fprintf(stderr, "fd_max = %d\n", fd_max);
        for(int i = 0; i <= fd_max; i++) {
            if( FD_ISSET(i, &read_fds) && i == server->listen_fd) {
                // only selects the listening port
                struct sockaddr_in addr;
                memset(&addr, 0, sizeof(addr));
                int conn_len = 0;
                // waiting client connect
                int conn_fd = accept(server->listen_fd, (struct sockaddr*)&addr, (socklen_t*)&conn_len);
                FD_SET( conn_fd, &master);
                fd_max = (fd_max > conn_fd ? fd_max : conn_fd);
                if (conn_fd < 0) {
                    if (errno == ENFILE) {
                        fprintf(stderr, "out of file descriptor table\n");
                        continue;
                    } else if (errno == EAGAIN || errno == EINTR) {
                        continue;
                    } else {
                        fprintf(stderr, "accept err\n");
                        fprintf(stderr, "code: %s\n", strerror(errno));
                        break;
                    }
                }
                for(int thread_i = 0; thread_i < MAX_CLIENT; thread_i++) {
                    if (t[thread_i] == NULL) {
                        // find a blank array space for new thread to create 
                        t[thread_i] = (pthread_t *) malloc(sizeof(pthread_t));
                        line_server_thread_args *thread_args;
                        thread_args = (line_server_thread_args *) malloc(sizeof(line_server_thread_args));
                        thread_args->server = server;
                        thread_args->conn_fd = conn_fd;
                        fprintf(stderr, "Server main thread create a new thread for receiving fd:%d\n", conn_fd);
                        pthread_create(t[thread_i], NULL, handle_request, (void *) thread_args);
                        break;
                    }
                }
                /*
                logout(server, i);
                FD_CLR(i, &master);
                */
            }
        }
        sleep(1);
    }
    return 1;
}

void line_server_destroy(line_server** server) {
    line_server* tmp = *server;
    *server = 0;
    if (!tmp) {
        return;
    }
    close(tmp->listen_fd);
    int i = getdtablesize() - 1;
    for (; i >= 0; --i) {
        if (tmp->client[i]) {
            free(tmp->client[i]);
        }
    }
    free(tmp->client);
    free(tmp);
}

//read config file
static int parse_arg(line_server* server, int argc, char** argv) {
    if (argc != 2) {
        return 0;
    }
    FILE* file = fopen(argv[1], "r");
    if (!file) {
        return 0;
    }
    fprintf(stderr, "reading config...\n");
    size_t keysize = 20, valsize = 20;
    char* key = (char*)malloc(sizeof(char) * keysize);
    char* val = (char*)malloc(sizeof(char) * valsize);
    ssize_t keylen, vallen;
    int accept_config_total = 2;
    int accept_config[2] = {0, 0};
    while ((keylen = getdelim(&key, &keysize, '=', file) - 1) > 0) {
        key[keylen] = '\0';
        vallen = getline(&val, &valsize, file) - 1;
        val[vallen] = '\0';
        fprintf(stderr, "config (%d, %s)=(%d, %s)\n", keylen, key, vallen, val);
        if (strcmp("path", key) == 0) {
            if (vallen <= sizeof(server->arg.path)) {
                strncpy(server->arg.path, val, vallen);
                accept_config[0] = 1;
            }
        } else if (strcmp("account_path", key) == 0) {
            if (vallen <= sizeof(server->arg.account_path)) {
                strncpy(server->arg.account_path, val, vallen);
                accept_config[1] = 1;
            }
        }
    }
    free(key);
    free(val);
    fclose(file);
    int i, test = 1;
    for (i = 0; i < accept_config_total; ++i) {
        test = test & accept_config[i];
    }
    if (!test) {
        fprintf(stderr, "config error\n");
        return 0;
    }
    return 1;
}


//this is where the server handle requests, you should write your code here
static void *handle_request(void *void_thread_args){
    line_server_thread_args *thread_args = (line_server_thread_args *) void_thread_args;
    line_server* server = thread_args->server;
    int conn_fd = thread_args->conn_fd;
    //fprintf(stderr, "Server thread receive fd:%d\n", conn_fd);
    int res_fd[2];
    if(pipe(res_fd) == -1){
        fprintf(stderr, "Error: Server create response pipe error.\n");
    }
    line_protocol_header header;
    memset(&header, 0, sizeof(header));
    while (recv_message(conn_fd, &header, sizeof(header))) {
        //fprintf(stderr, "recv header from client %s\n", (*(server->client))->account.user);
        //fprintf(stderr, "%d\n", header.req.op);
        if (header.req.magic != LINE_PROTOCOL_MAGIC_REQ) {
            write(res_fd[1], &header, sizeof(header));
            continue;
        }
        switch (header.req.op) {
            case LINE_PROTOCOL_OP_LOGIN:
                fprintf(stderr, "Client fd %d request Login\n", conn_fd);
                line_protocol_login req;
                if (complete_message_with_header(conn_fd, &header, &req)) {
                    char path[30];
                    sprintf(path, "../config/%s", req.message.body.user);
                    strcpy(server->arg.account_path, path);
                    login(server, conn_fd, &req);
                }
                break;
            case LINE_PROTOCOL_OP_REGISTER:
                fprintf(stderr, "Client fd %d request Register\n", conn_fd);
                line_protocol_login req2;
                if (complete_message_with_header(conn_fd, &header, &req2)) {
                    char path[30], account_info[100];
                    memset(path, 0, sizeof(path));
                    sprintf(path, "../config/%s", req2.message.body.user);
                    FILE *fp = fopen(path, "w+");
                    sprintf(account_info, "%s,%s\n", req2.message.body.user, req2.message.body.passwd);
                    fwrite(account_info, 1, strlen(account_info), fp);
                    fclose(fp);
                    memset(server->arg.account_path, 0, sizeof(server->arg.account_path));
                    strcpy(server->arg.account_path, path);
                    login(server, conn_fd, &req2);
                }
                break;
            case LINE_PROTOCOL_OP_SYNC_META: ;//Labels can only be followed by statements
                line_protocol_msg_file *meta;
                meta = (line_protocol_msg_file *) malloc(sizeof(line_protocol_msg_file));
                if (complete_message_with_header(conn_fd, &header, meta)) {
                    if(meta->message.body.is_msg == 1)
                        fprintf(stderr, "Client fd %d request sending message to %s\n", conn_fd, meta->message.body.recv_user);
                    else
                        fprintf(stderr, "Client fd %d request sending file to %s\n", conn_fd, meta->message.body.recv_user);
                    int ret = sync_meta_in_server(meta, conn_fd, server);
                    //if(ret == 1 && meta->message.body.finished == 1)
                    if(ret == 1)
                        ret = send_meta_to_client(meta, server->client, server->client[conn_fd]->account.user, res_fd[0]);
                }
                break;
            case LINE_PROTOCOL_OP_MATCH:
                fprintf(stderr, "match request from client.\n");
                line_protocol_match match_meta;
                if (complete_message_with_header(conn_fd, &header, &match_meta)) {
                    int ret = sync_match_to_server(match_meta, conn_fd, server);
                    if(ret == 1){
                        // to send unread messages to the client who start up matching
                        line_protocol_msg_file *unread_meta;
                        unread_meta = (line_protocol_msg_file *) malloc(sizeof(line_protocol_msg_file));
                        unread_meta->message.body.is_msg = 1;
                        strncpy(unread_meta->message.body.recv_user, server->client[conn_fd]->account.user, USER_LEN_MAX);
                        send_meta_to_client(unread_meta, server->client, match_meta.message.body.match_username, res_fd[0]);
                    }
                }
                break;
            case LINE_PROTOCOL_OP_UNMATCH:
                fprintf(stderr, "unmatch request from client.\n");
                line_protocol_match unmatch_meta;
                if (complete_message_with_header(conn_fd, &header, &unmatch_meta)) {
                    sync_unmatch_to_server(unmatch_meta, conn_fd, server);
                }
                break;
            case LINE_PROTOCOL_OP_ADD_FRIEND:
                fprintf(stderr, "add friend request from client.\n");
                line_protocol_msg_file *meta2;
                meta2 = (line_protocol_msg_file *) malloc(sizeof(line_protocol_msg_file));
                if (complete_message_with_header(conn_fd, &header, meta2)) {
                    sync_meta_in_server_add_friend(meta2, conn_fd, server);
                    send_add_friend_to_client(meta2, server->client, server->client[conn_fd]->account.user, res_fd[0]);
                }
                break;
            case LINE_PROTOCOL_OP_END:
                fprintf(stderr, "client logout\n");
                line_protocol_match match_meta2;
                if (complete_message_with_header(conn_fd, &header, &match_meta2)) {
                    int ret = send_logout_res_to_client(match_meta2, conn_fd, server);
                }
                break;
            case LINE_PROTOCOL_OP_LOG:
                fprintf(stderr, "log request from client.\n");
                line_protocol_msg_file *meta3;
                meta3 = (line_protocol_msg_file *) malloc(sizeof(line_protocol_msg_file));
                if (complete_message_with_header(conn_fd, &header, meta3)) {
                    sync_meta_in_server_log(meta3, conn_fd, server);
                    send_log_meta_to_client(meta3, conn_fd, server->client, server->client[conn_fd]->account.user, res_fd[0]);
                }
                break;
            default:
                fprintf(stderr, "unknown op %x\n", header.req.op);
                break;
        }
    }
    fprintf(stderr, "end of connection\n");
    logout(server, conn_fd);
    pthread_exit(NULL);
}

//open account file to get account information
static int get_account_info(
        line_server* server,  
        const char* user, 
        line_account_info* info) {
    fprintf(stderr, "%s\n", server->arg.account_path);
    FILE* file = fopen(server->arg.account_path, "r");
    if (!file) {
        return 0;
    }
    size_t buflen = 100;
    char* buf = (char*)malloc(sizeof(char) * buflen);
    memset(buf, 0, buflen);
    ssize_t len;
    int ret = 0;
    int line = 0;
    while ((len = getline(&buf, &buflen, file) - 1) > 0) {
        ++line;
        buf[len] = '\0';
        char* u = strtok(buf, ",");
        if (!u) {
            fprintf(stderr, "illegal form in account file, line %d\n", line);
            continue;
        }
        if (strcmp(user, u) == 0) {
            memcpy(info->user, user, strlen(user));
            char* passwd = strtok(NULL, ",");
            if (!passwd) {
                fprintf(stderr, "illegal form in account file, line %d\n", line);
                continue;
            }
            md5(passwd, strlen(passwd), info->passwd_hash);
            ret = 1;
            break;
        }
    }
    free(buf);
    fclose(file);
    return ret;
}

//handle the login request from client
static void login(
line_server* server, int conn_fd, line_protocol_login* login) {
    int succ = 1;
    line_client_info* info = (line_client_info*)malloc(sizeof(line_client_info));
    memset(info, 0, sizeof(line_client_info));
    if (!get_account_info(server, login->message.body.user, &(info->account))) {
        fprintf(stderr, "cannot find account\n");
        succ = 0;
    }
    if (succ && memcmp(login->message.body.passwd_hash,
                info->account.passwd_hash,
                MD5_DIGEST_LENGTH) != 0) {
        fprintf(stderr, "passwd miss match\n");
        succ = 0;
    }

    line_protocol_header header;
    memset(&header, 0, sizeof(header));
    header.req.magic = LINE_PROTOCOL_MAGIC_RES;
    header.res.magic = LINE_PROTOCOL_MAGIC_RES;
    header.res.op = LINE_PROTOCOL_OP_LOGIN;
    header.res.datalen = 0;
    if (succ) {
        if (server->client[conn_fd]) {
            free(server->client[conn_fd]);
        }
        info->conn_fd = conn_fd;
        info->match_username[0] = '\0';
        server->client[conn_fd] = info;
        header.res.status = LINE_PROTOCOL_STATUS_OK;
        header.res.client_id = info->conn_fd;
        char* homedir = get_user_homedir(server, info);
        mkdir(homedir, DIR_S_FLAG);
        free(homedir);
    } else {
        header.res.status = LINE_PROTOCOL_STATUS_FAIL;
        free(info);
    }
    send_message(conn_fd, &header, sizeof(header));
}

static void logout(line_server* server, int conn_fd) {
    free(server->client[conn_fd]);
    server->client[conn_fd] = 0;
    close(conn_fd);
}

static char* get_user_homedir(
    line_server* server, line_client_info* info) {
    char* ret = (char*)malloc(sizeof(char) * PATH_MAX);
    memset(ret, 0, PATH_MAX);
    sprintf(ret, "%s/%s", server->arg.path, info->account.user);
    return ret;
}

static int sync_add_friend_to_server(line_protocol_match req, int conn_fd, line_server *server){
    fprintf(stderr,"server: client wants to add friend\n");
    line_protocol_header response;
    memset(&response,0,sizeof(response));
    response.req.magic = LINE_PROTOCOL_MAGIC_RES;
    response.res.op = LINE_PROTOCOL_OP_MATCH;
    response.res.datalen = 0;
    int status = find_matching_client(req.message.body.match_username);
    if(status == 1){
        response.res.status = LINE_PROTOCOL_STATUS_OK;
        fprintf(stderr, "Server accepts add friend\n");

    }else{
        response.res.status = LINE_PROTOCOL_STATUS_FAIL;
        fprintf(stderr, "Server rejects match\n");
    }
    send_message(conn_fd, &response, sizeof(response));
    return status;
}

static int send_logout_res_to_client(line_protocol_match req, int conn_fd, line_server *server){
    line_protocol_header response;
    memset(&response,0,sizeof(response));
    response.req.magic = LINE_PROTOCOL_MAGIC_RES;
    response.res.op = LINE_PROTOCOL_OP_END;
    response.res.datalen = 0;
    send_message(conn_fd, &response, sizeof(response));
    logout(server, conn_fd);
    return 1;
}

static int sync_match_to_server(line_protocol_match req, int conn_fd, line_server *server){
    fprintf(stderr,"server: client wants to match\n");
    line_protocol_header response;
    memset(&response,0,sizeof(response));
    response.req.magic = LINE_PROTOCOL_MAGIC_RES;
    response.res.op = LINE_PROTOCOL_OP_MATCH;
    response.res.datalen = 0;
    int status = find_matching_client(req.message.body.match_username);
    if(status == 1){
        response.res.status = LINE_PROTOCOL_STATUS_OK;
        fprintf(stderr, "Server accepts match\n");
        strncpy(server->client[conn_fd]->match_username, req.message.body.match_username, USER_LEN_MAX);
        char talk_filename[FILE_NAME_MAX];
        sprintf(talk_filename, "../sdir/%s/talk_%s.csv", server->client[conn_fd]->account.user, req.message.body.match_username);
        fprintf(stderr, "%s\n", talk_filename);
        FILE *fp1 = fopen(talk_filename, "a");
        fclose(fp1);

        memset(talk_filename, 0, sizeof(talk_filename));
        sprintf(talk_filename, "../sdir/%s/talk_%s.csv", req.message.body.match_username, server->client[conn_fd]->account.user);
        fprintf(stderr, "%s\n", talk_filename);
        FILE *fp2 = fopen(talk_filename, "a");
        fclose(fp2);
    }else{
        response.res.status = LINE_PROTOCOL_STATUS_FAIL;
        fprintf(stderr, "Server rejects match\n");
    }
    send_message(conn_fd, &response, sizeof(response));
    return status;
}

static void sync_unmatch_to_server(line_protocol_match req, int conn_fd, line_server *server){
    line_protocol_header response;
    memset(&response,0,sizeof(response));
    response.req.magic = LINE_PROTOCOL_MAGIC_RES;
    response.res.magic = LINE_PROTOCOL_MAGIC_RES;
    response.res.op = LINE_PROTOCOL_OP_UNMATCH;
    response.res.datalen = 0;
    response.res.status = LINE_PROTOCOL_STATUS_OK;
    fprintf(stderr, "Server accepts unmatch\n");
    int match_fd = find_online_user_fd(server->client, server->client[conn_fd]->match_username);
    server->client[conn_fd]->match_username[0] = '\0';
    //server->client[match_fd]->match_username[0] = '\0';
    send_message(conn_fd, &response, sizeof(response));
}

static int find_matching_client(char *name){
    char path[1000];
    sprintf(path, "../config/%s", name);
    FILE *fp = fopen(path, "r");
    if(!fp)
        return 0;
    fclose(fp);
    return 1;
}
