#include "common.h"

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <bsd/md5.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>

void md5(const char* str, size_t len, uint8_t digest[MD5_DIGEST_LENGTH]) {
  MD5_CTX ctx;
  MD5Init(&ctx);
  MD5Update(&ctx, (const uint8_t*)str, len);
  MD5Final(digest, &ctx);
}

int md5_file(const char* path, uint8_t digest[MD5_DIGEST_LENGTH]) {
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    return 0;
  }
  char buf[4096];
  size_t len;
  MD5_CTX ctx;
  MD5Init(&ctx);
  while ((len = read(fd, buf, 4096)) > 0) {
    MD5Update(&ctx, (const uint8_t*)buf, len);
  }
  MD5Final(digest, &ctx);
  close(fd);
  return 1;
}

int recv_message(int conn_fd, void* message, size_t len) {
  if (len == 0) {
    return 0;
  }
  return recv(conn_fd, message, len, MSG_WAITALL) == len;
}

//used to receive complete header
int complete_message_with_header(
  int conn_fd, line_protocol_header* header, void* result) {
  memcpy(result, header->bytes, sizeof(line_protocol_header));
  return recv(conn_fd,
              result + sizeof(line_protocol_header),
              header->req.datalen,
              MSG_WAITALL) == header->req.datalen;
}

int send_message(int conn_fd, void* message, size_t len) {
  if (len == 0) {
    return 0;
  }
  return send(conn_fd, message, len, 0) == len;
}
        
int send_message_to_server_or_client(int send_fd, int recv_fd, char *msg, int msg_len, char *recv_user, line_protocol_msg_file *req){
    req->message.body.is_msg = 1;
    req->message.body.finished = 1;
    req->message.body.data_len = msg_len;
    strncpy(req->message.body.data, msg, DATA_LEN_MAX);
    strncpy(req->message.body.recv_user, recv_user, USER_LEN_MAX);
    
    //fprintf(stderr, "send message to fd %d.\n", send_fd);
    //fprintf(stderr, "Message content as follows:\nrecv_user:%s, msg:%s\n", req->message.body.recv_user, req->message.body.data);
    send_message(send_fd, req, sizeof(*req));
    //fprintf(stderr, "after send message of fd %d\n", send_fd);

    line_protocol_header header;
    memset(&header, 0, sizeof(header));
    recv_message(recv_fd, &header, sizeof(header)); //  接res
    //fprintf(stderr, "receive response: %d from fd %d.\n", header.res.status, recv_fd);
    if(header.res.status == LINE_PROTOCOL_STATUS_OK){
        return 1;
    }else if(header.res.status == LINE_PROTOCOL_STATUS_FAIL){
        return -1;
    }else{
        fprintf(stderr, "Client receive Error response from server. Expect to receive status ok or fail");
        return -1;
    }
}

int send_file_to_server_or_client(int send_fd, int recv_fd, char *msg, int msg_len, char *recv_user, line_protocol_msg_file *req, int Is_first, int Is_finish, char *file_name){
    req->message.body.is_msg = 0;
    req->message.body.first = Is_first;
    req->message.body.finished = Is_finish;
    req->message.body.data_len = msg_len;
    strncpy(req->message.body.filename, file_name, FILE_LEN_MAX);
    memcpy(req->message.body.data, msg, DATA_LEN_MAX);
    strncpy(req->message.body.recv_user, recv_user, USER_LEN_MAX);
    
    //fprintf(stderr, "send message to fd %d.\n", send_fd);
    //fprintf(stderr, "Message content as follows:\nrecv_user:%s, msg:%s\n", req->message.body.recv_user, req->message.body.data);
    //fprintf(stderr, "before send:%s\n", req->message.body.data);
    
    send_message(send_fd, req, sizeof(*req));
    //fprintf(stderr, "after send message of fd %d\n", send_fd);

    line_protocol_header header;
    memset(&header, 0, sizeof(header));
    recv_message(recv_fd, &header, sizeof(header)); //  接res
    //fprintf(stderr, "receive response: %d from fd %d.\n", header.res.status, recv_fd);
    if(header.res.status == LINE_PROTOCOL_STATUS_OK){
        return 1;
    }else if(header.res.status == LINE_PROTOCOL_STATUS_FAIL){
        return -1;
    }else{
        fprintf(stderr, "Client receive Error response from server. Expect to receive status ok or fail");
        return -1;
    }
}

int send_file_to_server_or_client_for_thread(int send_fd, int recv_fd, char *msg, int msg_len, char *recv_user, line_protocol_msg_file *req, int Is_first, int Is_finish, char *file_name){
    req->message.body.is_msg = 0;
    req->message.body.first = Is_first;
    req->message.body.finished = Is_finish;
    req->message.body.data_len = msg_len;
    strncpy(req->message.body.filename, file_name, FILE_LEN_MAX);
    memcpy(req->message.body.data, msg, DATA_LEN_MAX);
    strncpy(req->message.body.recv_user, recv_user, USER_LEN_MAX);
    
    //fprintf(stderr, "send message to fd %d.\n", send_fd);
    //fprintf(stderr, "Message content as follows:\nrecv_user:%s, msg:%s\n", req->message.body.recv_user, req->message.body.data);
    //fprintf(stderr, "before send:%s\n", req->message.body.data);
    
    send_message(send_fd, req, sizeof(*req));
    //fprintf(stderr, "after send message of fd %d\n", send_fd);

    line_protocol_header header;
    memset(&header, 0, sizeof(header));
    read(recv_fd, &header, sizeof(header)); //  接res
    //fprintf(stderr, "receive response: %d from fd %d.\n", header.res.status, recv_fd);
    if(header.res.status == LINE_PROTOCOL_STATUS_OK){
        return 1;
    }else if(header.res.status == LINE_PROTOCOL_STATUS_FAIL){
        return -1;
    }else{
        fprintf(stderr, "Client receive Error response from server. Expect to receive status ok or fail");
        return -1;
    }
}

int send_add_friend_req_to_server_or_client(int send_fd, int recv_fd, char *sending_user, char *recv_user, line_protocol_msg_file *req){
    strcpy(req->message.body.sender,sending_user);
	strcpy(req->message.body.recv_user, recv_user);
	send_message(send_fd, req, sizeof(*req));
	line_protocol_header header;
    memset(&header, 0, sizeof(header));
    recv_message(recv_fd, &header, sizeof(header)); //  接res
	if(header.res.status == LINE_PROTOCOL_STATUS_OK){
        return 1;
    }else if(header.res.status == LINE_PROTOCOL_STATUS_FAIL){
        return -1;
    }else{
        fprintf(stderr, "Client receive Error response from server. Expect to receive status ok or fail");
        return -1;
    }
}

int send_log_req_to_server(int send_fd, int recv_fd, char *sending_user, char *recv_user, line_protocol_msg_file *req){
    strcpy(req->message.body.sender,sending_user);
	strcpy(req->message.body.recv_user, recv_user);
	send_message(send_fd, req, sizeof(*req));
	line_protocol_header header;
    memset(&header, 0, sizeof(header));
    recv_message(recv_fd, &header, sizeof(header)); //  接res
	if(header.res.status == LINE_PROTOCOL_STATUS_OK){
        return 1;
    }else if(header.res.status == LINE_PROTOCOL_STATUS_FAIL){
        return -1;
    }else{
        fprintf(stderr, "Client receive Error response from server. Expect to receive status ok or fail");
        return -1;
    }
}

int send_log_to_client(int send_fd, int recv_fd, char *msg, int msg_len, char *recv_user, line_protocol_msg_file *req){
    req->message.body.is_msg = 0;
    req->message.body.first = 1;
    req->message.body.finished = 1;
    req->message.body.data_len = msg_len;
    //strncpy(req->message.body.filename, file_name, FILE_LEN_MAX);
    strncpy(req->message.body.data, msg, DATA_LEN_MAX);
    strncpy(req->message.body.recv_user, recv_user, USER_LEN_MAX);
    
    //fprintf(stderr, "send message to fd %d.\n", send_fd);
    //fprintf(stderr, "Message content as follows:\nrecv_user:%s, msg:%s\n", req->message.body.recv_user, req->message.body.data);
    send_message(send_fd, req, sizeof(*req));
    //fprintf(stderr, "after send message of fd %d\n", send_fd);

    line_protocol_header header;
    memset(&header, 0, sizeof(header));
    recv_message(recv_fd, &header, sizeof(header)); //  接res
    //fprintf(stderr, "receive response: %d from fd %d.\n", header.res.status, recv_fd);
    if(header.res.status == LINE_PROTOCOL_STATUS_OK){
        return 1;
    }else if(header.res.status == LINE_PROTOCOL_STATUS_FAIL){
        return -1;
    }else{
        fprintf(stderr, "Client receive Error response from server. Expect to receive status ok or fail");
        return -1;
    }
}
