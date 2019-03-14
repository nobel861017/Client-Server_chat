#include "client.h"
#include "common.h"
#include "connect.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <utime.h>
#include <time.h>
#include <sys/types.h>
#include <fcntl.h>


#define PATH_LEN_MAX 30
#define FILE_NAME_MAX 30

static int parse_arg(line_client* client, int argc, char** argv);
static int login(line_client* client);
static int send_match_req_to_server(int conn_fd, char *match_name, int recv_res_fd);
static int send_unmatch_req_to_server(int conn_fd, char *match_name, int recv_res_fd);
static void print_sticker(int sticker_num);
static char *find_msg_start_ptr(char *msg);
static void get_print_time(char *ptr, int time);

static int send_meta_to_server(int conn_fd, int recv_res_fd, int is_msg, char *msg, int msg_len, char *path_name, char *recv_user, int Is_finish, int Is_first){
    line_protocol_msg_file req;
    memset(&req, 0, sizeof(req));
    req.message.header.req.magic = LINE_PROTOCOL_MAGIC_REQ;
    req.message.header.req.op = LINE_PROTOCOL_OP_SYNC_META;
    req.message.header.req.datalen = sizeof(req) - sizeof(req.message.header);
    
    if(is_msg == 1){
        return send_message_to_server_or_client(conn_fd, recv_res_fd, msg, msg_len, recv_user, &req);
    }
    else if(is_msg == 0){
        return send_file_to_server_or_client_for_thread(conn_fd, recv_res_fd, msg, msg_len, recv_user, &req, Is_first, Is_finish, path_name);
    }
}

static int send_meta_to_server_req_log(int conn_fd, int recv_res_fd, char *sending_user, char *recv_user){
    line_protocol_msg_file req;
    memset(&req, 0, sizeof(req));
    req.message.header.req.magic = LINE_PROTOCOL_MAGIC_REQ;
    req.message.header.req.op = LINE_PROTOCOL_OP_LOG;
    req.message.header.req.datalen = sizeof(req) - sizeof(req.message.header);
    return send_log_req_to_server(conn_fd, recv_res_fd, sending_user, recv_user, &req);
}

static int send_meta_to_server_add_friend(int conn_fd, int recv_res_fd, char *sending_user, char *recv_user){
    line_protocol_msg_file req;
    memset(&req, 0, sizeof(req));
    req.message.header.req.magic = LINE_PROTOCOL_MAGIC_REQ;
    req.message.header.req.op = LINE_PROTOCOL_OP_ADD_FRIEND;
    req.message.header.req.datalen = sizeof(req) - sizeof(req.message.header);
    return send_add_friend_req_to_server_or_client(conn_fd, recv_res_fd, sending_user, recv_user, &req);
}
static int sync_meta_in_client_add_friend(line_protocol_msg_file *req, int conn_fd, char *username){
    line_protocol_header response;
    memset(&response,0,sizeof(response));
    response.res.magic = LINE_PROTOCOL_MAGIC_RES;
    response.res.op = LINE_PROTOCOL_OP_ADD_FRIEND;
    response.res.datalen = 0;
    response.res.status = LINE_PROTOCOL_STATUS_OK;

    if(req->message.header.req.op == LINE_PROTOCOL_OP_ADD_FRIEND){
        fprintf(stderr, "add friend to friend file list\n");
        char path[PATH_LEN_MAX], buff[USER_LEN_MAX];
        memset(path, 0, sizeof(path));
        sprintf(path, "../cdir/%s/friend_list", username);
        FILE *fp = fopen(path, "a+");
        sprintf(buff, "%s\n", req->message.body.sender);
        fwrite(buff, strlen(buff), 1, fp);
        fclose(fp);
    }
    return send_message(conn_fd, &response, sizeof(response));
}

static int sync_meta_in_client_log(line_protocol_msg_file *req, int conn_fd, char *username){
    line_protocol_header response;
    memset(&response,0,sizeof(response));
    response.res.magic = LINE_PROTOCOL_MAGIC_RES;
    response.res.op = LINE_PROTOCOL_OP_LOG;
    response.res.datalen = 0;
    response.res.status = LINE_PROTOCOL_STATUS_OK;
    char path[FILE_NAME_MAX], buf[MESSAGE_LEN_MAX], c;
    memset(path, 0, sizeof(path));
    sprintf(path, "../cdir/%s/log", username);
    fprintf(stderr, "historic messages\n");
    /*int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | REG_S_FLAG);
    chmod(path, 0777);
    int len = write(fd, req->message.body.data, req->message.body.data_len);
    close(fd);*/
    FILE *fp1 = fopen(path, "w");
    fwrite(req->message.body.data, req->message.body.data_len, 1, fp1);
    fclose(fp1);
    //fprintf(stderr, "len = %d, datalen = %d\n", sizeof(req->message.body.data), req->message.body.data_len);
    FILE *fp = fopen(path, "r");
    while ((c = getc(fp)) != EOF)
        putchar(c);
    fclose(fp);

    // send response OK
    fprintf(stderr, "Client B receive and response with %d status code.\n", response.res.status);
    return send_message(conn_fd, &response, sizeof(response));
}

static int sync_meta_in_client(line_protocol_msg_file *req, int conn_fd, char *username){
    line_protocol_header response;
    memset(&response,0,sizeof(response));
    response.res.magic = LINE_PROTOCOL_MAGIC_RES;
    response.res.op = LINE_PROTOCOL_OP_SYNC_META;
    response.res.datalen = 0;
    response.res.status = LINE_PROTOCOL_STATUS_OK;
    //fprintf(stderr, "is_msg == %d\n", req->message.body.is_msg);
    if(req->message.body.is_msg == 1){
        // handle sending messages
        if(req->message.body.data[0] == '1'){
            fprintf(stderr, "Client B receive message as follow:\n");
            //puts(req->message.body.data);
            char decrypt_message[DATA_LEN_MAX];
            memset(decrypt_message, 0, sizeof(decrypt_message));
            strcpy(decrypt_message, req->message.body.data);
            // Caesar Cypher Algorithm Decryption
            for(int i = 15; (i < DATA_LEN_MAX && decrypt_message[i] != '\0'); i++)
                decrypt_message[i] = decrypt_message[i] - 3;

            char send_time_char[DATA_LEN_MAX];
            char *msg_start_ptr = find_msg_start_ptr(decrypt_message);
            int send_char_i = 0; 
            for(char *char_ptr = &(decrypt_message[4]); char_ptr != msg_start_ptr; char_ptr ++, send_char_i ++){
                send_time_char[send_char_i] = *char_ptr;
            }
            send_time_char[send_char_i-1] = '\0';
            int send_time = atoi(send_time_char);
            time_t t_now;
            t_now = time(NULL);
            int time_diff = (int)t_now - send_time;
            char print_time[DATA_LEN_MAX];
            get_print_time(print_time, time_diff);
            if(msg_start_ptr[0] == ':' && msg_start_ptr[1] == 's'){
                // Is sticker
                print_sticker(msg_start_ptr[3] - '0');
                printf(" (%s)\n", print_time);
            }else{
                printf("%s (%s)\n", msg_start_ptr, print_time);
            }
        }
    }else if(req->message.body.is_msg == 0){
        // handle receiving file
        int fd;
        char save_filename[FILE_NAME_MAX];
        sprintf(save_filename, "../cdir/%s/%s", username, req->message.body.filename);
        fprintf(stderr, "Client B receive file as follow: %s\n", save_filename);
        FILE *fptr;
        if(req->message.body.first){
            //fptr = fopen(save_filename, "wb+");
            fd = open(save_filename, O_WRONLY | O_CREAT | O_TRUNC, REG_S_FLAG);
        }else{
            fd = open(save_filename, O_WRONLY | O_CREAT | O_APPEND, REG_S_FLAG);
        }
        //char decrypt_message[FILE_NAME_MAX];
        //memset(decrypt_message, 0, sizeof(decrypt_message));
        //strcpy(decrypt_message, req->message.body.data);
        // Caesar Cypher Algorithm Decryption
        //for(int i = 0; i < req->message.body.data_len; i++)
        //    decrypt_message[i] = decrypt_message[i] - 3;
        //fwrite(req->message.body.data, sizeof(char), req->message.body.data_len, fptr);
        //write(fd, decrypt_message, req->message.body.data_len);
        write(fd, req->message.body.data, req->message.body.data_len);
        //if(req->message.body.finished)
        close(fd);
        /*int fd = open(save_filename,O_WRONLY | O_CREAT | O_TRUNC, REG_S_FLAG);
        write(fd, req->message.body.data, req->message.body.data_len);
        close(fd);*/
        if(req->message.body.finished == 1){
            char print_to_user[DATA_LEN_MAX];
            sprintf(print_to_user, "File: %s received at %s", req->message.body.filename, save_filename);
        }
    }
    else{
        fprintf(stderr, "Option set to LINE_PROTOCOL_OP_SYNC_META but receive is_msg to be not 0 or 1.");
        response.res.status = LINE_PROTOCOL_STATUS_FAIL;
        send_message(conn_fd, &response, sizeof(response));
        return -1;
    }

    // send response OK
    fprintf(stderr, "Client B receive and response with %d status code.\n", response.res.status);
    return send_message(conn_fd, &response, sizeof(response));
}
static void send_file_to_server(int conn_fd, int recv_res_fd, char *path_name, char *sending_user, char *recv_user){
    int fd, datalen, first = 1, BUF_MAX = 20;
    //char buf[BUF_MAX], parse_path[PATH_LEN_MAX];
    char buf[FILE_LEN_MAX], parse_path[PATH_LEN_MAX];
    sprintf(parse_path, "../cdir/%s/%s", sending_user, path_name);
    fd = open(parse_path, O_RDONLY);
    //FILE *file_p = fopen(parse_path, "rb");
    int counter = 0;
    while(1){
        datalen = read(fd,buf,sizeof(buf));
        //datalen = fread(buf, sizeof(char), FILE_LEN_MAX, file_p);
        //fprint(stderr, "datalen = %d\n", datalen);
        if(datalen < 0) break;
        //fprintf(stderr, "data len = %d\n", datalen);

        // Caesar Cypher Algorithm Encryption
        //for(int i = 0; i < datalen; i++)
        //    buf[i] = buf[i] + 3;
        if(datalen == 0){
            if(first){
                //fprintf(stderr, "send %d datalen==0, first: %s", counter, parse_path);
                send_meta_to_server(conn_fd, recv_res_fd, 0, buf, datalen, path_name, recv_user, 1, 1);
                first = 0;
            }
            else{
                //fprintf(stderr, "send %d datalen==0: %s", counter, parse_path);
                send_meta_to_server(conn_fd, recv_res_fd, 0, buf, datalen, path_name, recv_user, 1, 0);
            }
            break;
        }
        else{
            if(first){
                //fprintf(stderr, "send %d first: %s, len:%d\n", counter, parse_path, datalen);
                send_meta_to_server(conn_fd, recv_res_fd, 0, buf, datalen, path_name, recv_user, 0, 1);
                first = 0;
            }
            else{
                //fprintf(stderr, "send %d: %s, len:%d\n", counter, parse_path, datalen);
                send_meta_to_server(conn_fd, recv_res_fd, 0, buf, datalen, path_name, recv_user, 0, 0);
            }
        }
        memset(buf, 0, sizeof(buf));
        counter++;
        //if(counter > 2) break;
    }
    close(fd);
    
}

static void *send_file_thread(void *void_thread_args){
    fprintf(stderr, "Enter send_file_thread\n");
    thread_args_send_file *args = (thread_args_send_file *) void_thread_args;
    send_file_to_server(args->conn_fd, args->recv_res_fd, args->file_name, args->sending_user, args->recv_user);
    fprintf(stderr, "finish sending file %s\n", args->file_name);
    pthread_exit(NULL);
}

static void *interface_send_message(void *void_thread_args){
    fprintf(stderr, "Enter interface_send_message\n");
    thread_args_interface *args = (thread_args_interface *) void_thread_args;
    char msg[DATA_LEN_MAX];
    char exit_symbol[] = ":q";
    char send_file_symbol[] = ":f";
    char add_friend_symbol[] = ":a";
    char list_friend_symbol[] = ":l";
    fgets(msg, DATA_LEN_MAX, stdin);
    puts("Please enter what you want to say");
    while(1){
        fgets(msg, DATA_LEN_MAX, stdin);
        //fprintf(stderr, "%s", msg);
        for(int rstrip_i = strlen(msg)-1; rstrip_i >= 0; rstrip_i --){
            if(msg[rstrip_i] == '\n'){
                msg[rstrip_i] = '\0';
                if(strncmp(msg, exit_symbol, strlen(exit_symbol)+1) == 0 || strncmp(msg, send_file_symbol, strlen(send_file_symbol)+1) == 0 || strncmp(msg, add_friend_symbol, strlen(add_friend_symbol)+1) == 0 || strncmp(msg, list_friend_symbol, strlen(list_friend_symbol)+1) == 0)
                    break;
                // Caesar Cypher Algorithm Encryption
                for(int i = 0; (i < DATA_LEN_MAX && msg[i] != '\0'); i++)
                    msg[i] = msg[i] + 3;
                break;
            }
        }
        if(strncmp(msg, exit_symbol, strlen(exit_symbol)+1) == 0)
            break;
        else if(strncmp(msg, send_file_symbol, strlen(send_file_symbol)+1) == 0){
            puts("Enter number of files followed by file names with space between: ");
            int file_num;
            scanf("%d", &file_num);
            char file_table[file_num][FILE_NAME_MAX];
            for(int i = 0; i < file_num; i++){
                scanf("%s", file_table[i]);
            }
            thread_args_send_file send_file_args[file_num];
            for(int i = 0; i < file_num; i++){
                //fprintf(stderr, "sending file %s\n", file_table[i]);
                //memset(&send_file_args[i], 0, sizeof(send_file_args[i]));
                send_file_args[i].conn_fd = args->conn_fd;
                send_file_args[i].recv_res_fd = args->recv_res_fd;
                strcpy(send_file_args[i].file_name, file_table[i]);
                send_file_args[i].sending_user = args->sending_user;
                send_file_args[i].recv_user = args->recv_user;
                fprintf(stderr, "send file %s\n", send_file_args[i].file_name);
                pthread_create(&(send_file_args[i].tid), NULL, send_file_thread, &(send_file_args[i]));
                //pthread_join((send_file_args[i].tid), NULL);
                //pthread_detach(send_file_args[i].tid);
                
                //send_file_to_server(args->conn_fd, args->recv_res_fd, file_table[i], args->sending_user, args->recv_user);
            }
            fprintf(stderr, "finish sending all files\n");
            for(int i = 0; i < file_num; i++)
                pthread_join(send_file_args[i].tid, NULL);
            fgets(msg, DATA_LEN_MAX, stdin); // clear stdin
            memset(msg, 0, sizeof(msg));
            

        }
        else if(strncmp(msg, add_friend_symbol, strlen(add_friend_symbol)+1) == 0){
            int ret = send_meta_to_server_add_friend(args->conn_fd, args->recv_res_fd, args->sending_user, args->recv_user);
            if(ret == 1){
                fprintf(stderr, "add friend to friend file list\n");
                char path[PATH_LEN_MAX], buff[USER_LEN_MAX];
                memset(path, 0, sizeof(path));
                sprintf(path, "../cdir/%s/friend_list", args->sending_user);
                FILE *fp = fopen(path, "a+");
                sprintf(buff, "%s\n", args->recv_user);
                fwrite(buff, strlen(buff), 1, fp);
                fclose(fp);
            }
        }
        else if(strncmp(msg, list_friend_symbol, strlen(list_friend_symbol)+1) == 0){
            fprintf(stderr, "send log req to server\n");
            int ret = send_meta_to_server_req_log(args->conn_fd, args->recv_res_fd, args->sending_user, args->recv_user);
            if(ret == 1){
                fprintf(stderr, "log chatting list\n");
                
            }
        }
        else{
            int type = send_meta_to_server(args->conn_fd, args->recv_res_fd, 1, msg, strlen(msg)+1, NULL, args->recv_user,1,1);
        }
        
    }
    send_unmatch_req_to_server(args->conn_fd, args->recv_user, args->recv_res_fd);
    fprintf(stderr, "Exit interface_send_message\n");
    pthread_exit(NULL);
}

// to handle requests from server
static void *handle_request(void *void_thread_args){
    thread_args_handle *args = (thread_args_handle *) void_thread_args;
    int conn_fd = args->conn_fd, send_res_fd = args->send_res_fd;
    line_protocol_header header;
    memset(&header, 0, sizeof(header));
    while (recv_message(conn_fd, &header, sizeof(header))) {
        //fprintf(stderr, "recv header from server %s\n", (*(server->client))->account.user);
        //fprintf(stderr, "%d\n", header.req.op);
        if (header.req.magic == LINE_PROTOCOL_MAGIC_RES) {
            write(send_res_fd, &header, sizeof(header));
            if(header.req.op == LINE_PROTOCOL_OP_END) break;
            fprintf(stderr, "handle_request receive response of op code: %d\n", header.req.op);
            continue;
        }
        // LINE_PROTOCOL_MAGIC_REQ
        switch (header.req.op) {
            case LINE_PROTOCOL_OP_SYNC_META: ;//Labels can only be followed by statements
                line_protocol_msg_file *meta;
                meta = (line_protocol_msg_file *) malloc(sizeof(line_protocol_msg_file));
                if (complete_message_with_header(conn_fd, &header, meta)) {
                    if(meta->message.body.is_msg == 1)
                        fprintf(stderr, "Server fd %d request sending message to %s\n", conn_fd, meta->message.body.recv_user);
                    else
                        fprintf(stderr, "Server fd %d request sending file to %s\n", conn_fd, meta->message.body.recv_user);
                    int ret = sync_meta_in_client(meta, conn_fd, args->username);
                    //if(ret == 1 && meta->message.body.is_msg == 0 && meta->message.body.finished == 1)
                    //    show_file_message(meta, server);
                }else{
                    fprintf(stderr, "Error when complete_message_with_header\n");
                }
                break;
            case LINE_PROTOCOL_OP_ADD_FRIEND:
                fprintf(stderr, "add friends!\n");
                line_protocol_msg_file *meta2;
                meta2 = (line_protocol_msg_file *) malloc(sizeof(line_protocol_msg_file));
                if (complete_message_with_header(conn_fd, &header, meta2)) {
                    int ret = sync_meta_in_client_add_friend(meta2, conn_fd, args->username);
                }else{
                    fprintf(stderr, "Error when complete_message_with_header\n");
                }
                break;
            case LINE_PROTOCOL_OP_LOG:
                fprintf(stderr, "print log\n");
                line_protocol_msg_file *meta3;
                meta3 = (line_protocol_msg_file *) malloc(sizeof(line_protocol_msg_file));
                if (complete_message_with_header(conn_fd, &header, meta3)) {
                    int ret = sync_meta_in_client_log(meta3, conn_fd, args->username);
                }else{
                    fprintf(stderr, "Error when complete_message_with_header\n");
                }
                break;
            default:
                fprintf(stderr, "unknown op %x\n", header.req.op);
                break;
        }
    }
    fprintf(stderr, "Close chatting window\n");
    pthread_exit(NULL);
}

//read config file
static int parse_arg(line_client* client, int argc, char** argv) {
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
  int accept_config_total = 5;
  int accept_config[5] = {0, 0, 0, 0, 0};
  while ((keylen = getdelim(&key, &keysize, '=', file) - 1) > 0) {
    key[keylen] = '\0';
    vallen = getline(&val, &valsize, file) - 1;
    val[vallen] = '\0';
    fprintf(stderr, "config (%d, %s)=(%d, %s)\n", keylen, key, vallen, val);
    if (strcmp("name", key) == 0) {
      if (vallen <= sizeof(client->arg.name)) {
        strncpy(client->arg.name, val, vallen);
        accept_config[0] = 1;
      }
    } else if (strcmp("server", key) == 0) {
      if (vallen <= sizeof(client->arg.server)) {
        strncpy(client->arg.server, val, vallen);
        accept_config[1] = 1;
      }
    } else if (strcmp("user", key) == 0) {
      if (vallen <= sizeof(client->arg.user)) {
        strncpy(client->arg.user, val, vallen);
        accept_config[2] = 1;
      }
    } else if (strcmp("passwd", key) == 0) {
      if (vallen <= sizeof(client->arg.passwd)) {
        strncpy(client->arg.passwd, val, vallen);
        accept_config[3] = 1;
      }
    } else if (strcmp("path", key) == 0) {
      if (vallen <= sizeof(client->arg.path)) {
        strncpy(client->arg.path, val, vallen);
        accept_config[4] = 1;
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

void client_info(line_client* tmp, char *u, char *p){
    memset(tmp->arg.user, 0, sizeof(tmp->arg.user));
    memset(tmp->arg.passwd, 0, sizeof(tmp->arg.passwd));
    //strcpy(tmp->arg.name, "b05902121");
    strcpy(tmp->arg.user, u);
    strcpy(tmp->arg.passwd, p);
    //strcpy(tmp->arg.server, "localhost");
    //strcpy(tmp->arg.path, "../cdir");
}

//read config file, and connect to server
void line_client_init(line_client** client, int argc, char** argv) {
    line_client* tmp = (line_client*)malloc(sizeof(line_client));
    if (!tmp) {
        fprintf(stderr, "client malloc fail\n");
        return;
    }
    memset(tmp, 0, sizeof(line_client));
    if (!parse_arg(tmp, argc, argv)) {
        fprintf(stderr, "Usage: %s [config file]\n", argv[0]);
        free(tmp);
        return;
    }
    char username[USER_LEN_MAX], password[PATH_LEN_MAX];
    puts("Login: 0, Signup:1");
    while(1){
        scanf("%d", &(tmp->Is_register));
        puts("Please enter user name:");
        scanf("%s", username);
        puts("Please enter pass word:");
        scanf("%s", password);
        if(tmp->Is_register == 1){
            char dir[PATH_LEN_MAX];
            sprintf(dir, "../cdir/%s", username);
            mkdir(dir, S_IRWXU | S_IRWXG | S_IRWXO); // mode: 777
        }
        if(tmp->Is_register == 1 || tmp->Is_register == 0)
            break;
        puts("Please enter 0 or 1");
    }
    client_info(tmp, username, password);
    int fd = client_start(tmp->arg.name, tmp->arg.server);
    if (fd < 0) {
        fprintf(stderr, "connect fail\n");
        free(tmp);
        return;
    }
    tmp->conn_fd = fd;
    *client = tmp;
}
static int send_logout_request_to_server(int conn_fd, int recv_res_fd){
    line_protocol_match req;
    memset(&req, 0, sizeof(req));
    req.message.header.req.magic = LINE_PROTOCOL_MAGIC_REQ;
    req.message.header.req.op = LINE_PROTOCOL_OP_END;
    req.message.header.req.datalen = sizeof(req) - sizeof(req.message.header);
    send_message(conn_fd, &req, sizeof(req));
    line_protocol_header header;
    memset(&header, 0, sizeof(header));
    read(recv_res_fd, &header, sizeof(header));
    if(header.res.status == LINE_PROTOCOL_STATUS_OK){
        return 1;
    }else if(header.res.status == LINE_PROTOCOL_STATUS_FAIL){
        return -1;
    }else{
        fprintf(stderr, "Error client receive error status code, not OK or FAIL.\n");
        return -1;
    }
}
static int send_match_req_to_server(int conn_fd, char *match_name, int recv_res_fd){
    line_protocol_match req;
    memset(&req, 0, sizeof(req));
    req.message.header.req.magic = LINE_PROTOCOL_MAGIC_REQ;
    req.message.header.req.op = LINE_PROTOCOL_OP_MATCH;
    req.message.header.req.datalen = sizeof(req) - sizeof(req.message.header);
    strncpy(req.message.body.match_username, match_name, USER_LEN_MAX);
    //fprintf(stderr, "send server matching client username\n");
    send_message(conn_fd, &req, sizeof(req));
    
    line_protocol_header header;
    memset(&header, 0, sizeof(header));
    read(recv_res_fd, &header, sizeof(header));
    fprintf(stderr, "Match request response with magic:%d, op:%d, status:%d\n", header.req.magic, header.res.op, header.res.status);
    if(header.res.status == LINE_PROTOCOL_STATUS_OK){
        fprintf(stderr, "start chatting with %s\n", match_name);
        return 1;
    }else if(header.res.status == LINE_PROTOCOL_STATUS_FAIL){
        fprintf(stderr, "%s user doesn't exist.\n", match_name);
        return -1;
    }else{
        fprintf(stderr, "Error client receive error status code, not OK or FAIL.\n");
        return -1;
    }
}

static int send_unmatch_req_to_server(int conn_fd, char *match_name, int recv_res_fd){
    line_protocol_match req;
    memset(&req, 0, sizeof(req));
    req.message.header.req.magic = LINE_PROTOCOL_MAGIC_REQ;
    req.message.header.req.op = LINE_PROTOCOL_OP_UNMATCH;
    req.message.header.req.datalen = sizeof(req) - sizeof(req.message.header);
    strncpy(req.message.body.match_username, match_name, USER_LEN_MAX);
    //fprintf(stderr, "send server matching client username\n");
    send_message(conn_fd, &req, sizeof(req));
    
    line_protocol_header header;
    memset(&header, 0, sizeof(header));
    read(recv_res_fd, &header, sizeof(header));
    //fprintf(stderr, "UnMatch request response with magic:%d, op:%d, status:%d\n", header.req.magic, header.res.op, header.res.status);
    if(header.res.status == LINE_PROTOCOL_STATUS_OK){
        return 1;
    }else if(header.res.status == LINE_PROTOCOL_STATUS_FAIL){
        fprintf(stderr, "Client cannot unmatch %s user.\n", match_name);
        return -1;
    }else{
        fprintf(stderr, "Error client receive error status code, expect OK only.\n");
        return -1;
    }
}

void User_Interface(line_client* client){
    int res_fd[2];
    if(pipe(res_fd) == -1){
        fprintf(stderr, "Client create pipe error\n");
        return;
    }
    pthread_t thread_for_handle;
    thread_args_handle handle_args;
    handle_args.conn_fd = client->conn_fd;
    handle_args.send_res_fd = res_fd[1];
    handle_args.username = client->arg.user;
    pthread_create(&thread_for_handle, NULL, handle_request, (void *) &handle_args);
    while(1){
        puts("Chat: c / Quit: q");
        char c;
        scanf("\n%c", &c);
        if(c == 'c'){
            puts("Insert name who you want to chat with: ");
            char match_username[USER_LEN_MAX];
            scanf("%s", match_username);
            // send request to server to match client:

            int rt = send_match_req_to_server(client->conn_fd, match_username, res_fd[0]);
            if(rt == 1){
                pthread_t thread_for_interface;
                thread_args_interface interface_args;
                interface_args.conn_fd = client->conn_fd;
                interface_args.recv_res_fd = res_fd[0];
                interface_args.sending_user = client->arg.user;
                interface_args.recv_user = match_username;
                pthread_create(&thread_for_interface, NULL, interface_send_message, (void *) &interface_args);
                pthread_join(thread_for_interface, NULL);
                fprintf(stderr, "Client finish chatting with %s.\n", match_username);
            }
        }else if(c == 'q'){
            // Not Implemented Error
            close(res_fd[0]); close(res_fd[1]);
            fprintf(stderr, "logout from server\n");
            int ret = send_logout_request_to_server(client->conn_fd, res_fd[0]);
            if(ret == 1){
                pthread_join(thread_for_handle, NULL);
                return;
            }
        }else{
            puts("Error command");
        }
    }
}

//this is where client sends request, you sould write your code here
int line_client_run(line_client* client) {
    if (!login(client)) {
        fprintf(stderr, "login fail\n");
        fprintf(stderr, "username or passwd incorrect\n");
        return 0;
    }
    fprintf(stderr, "login success\n");
    User_Interface(client);

    return 1;
}

void line_client_destroy(line_client** client) {
  line_client* tmp = *client;
  *client = 0;
  if (!tmp) {
    return;
  }
  close(tmp->conn_fd);
  free(tmp);
}


static int login(line_client* client) {
  line_protocol_login req;
  memset(&req, 0, sizeof(req));
  req.message.header.req.magic = LINE_PROTOCOL_MAGIC_REQ;
  if(client->Is_register == 0) req.message.header.req.op = LINE_PROTOCOL_OP_LOGIN;
  else req.message.header.req.op = LINE_PROTOCOL_OP_REGISTER;
  req.message.header.req.datalen = sizeof(req) - sizeof(req.message.header);
  memcpy(req.message.body.user, client->arg.user, strlen(client->arg.user));
  strcpy(req.message.body.passwd, client->arg.passwd);
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

static void print_sticker(int sticker_num){
	    char filename[FILE_LEN_MAX];
	    sprintf(filename, "../cdir/stickers/sticker%d.txt", sticker_num);
	    FILE *fp = fopen(filename, "r");
	    if(fp == NULL){
	        fprintf(stderr, "sticker not found.\n");
	        return;
	    }
	    char buf[DATA_LEN_MAX];
	    while(fgets(buf, sizeof(buf), fp) != NULL){
	        printf("%s", buf);
	    }
	}
	static char *find_msg_start_ptr(char *msg){
	    int count_comma = 0;
	    for(int i = 0; i < DATA_LEN_MAX; i++){
	        if(msg[i] == ','){
	            count_comma ++;
	            if(count_comma >= 3)
	                return &(msg[i+1]);
	        }
	    }
	    return msg;
	}

static void get_print_time(char *ptr, int time){
    if(time < 60){
        sprintf(ptr, "%d seconds ago", time);
    }else if(time < 3600){
        sprintf(ptr, "%d minutes ago", (time/60) + 1);
    }else if(time < 3600 * 24){
        sprintf(ptr, "%d hours ago", (time / 3600) + 1);
    }else{
        sprintf(ptr, "%d days ago", (time / (3600 * 24)) + 1);
    }
}
