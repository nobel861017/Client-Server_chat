#ifndef _LINE_COMMON_
#define _LINE_COMMON_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <bsd/md5.h>
#include <sys/stat.h>

#include <pthread.h>
/*
 * protocol
 */

#define USER_LEN_MAX 30
#define PASSWD_LEN_MAX 30
#define FILE_NAME_MAX 30
#define FILE_LEN_MAX 40960
#define DATA_LEN_MAX 40960
#define TOTAL_MSG_MAX 20
#define MESSAGE_LEN_MAX 100

#define DIR_S_FLAG (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)//permission you can use to create new file
#define REG_S_FLAG (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)//permission you can use to create new directory

typedef enum {
    LINE_PROTOCOL_MAGIC_REQ = 0x90,
    LINE_PROTOCOL_MAGIC_RES = 0x91,
} line_protocol_magic;

typedef enum {
    LINE_PROTOCOL_OP_LOGIN = 0x00,
    LINE_PROTOCOL_OP_SYNC_META = 0x01,
    LINE_PROTOCOL_OP_LOG = 0x02,
    LINE_PROTOCOL_OP_REGISTER = 0x03,
    LINE_PROTOCOL_OP_END = 0x04,
    LINE_PROTOCOL_OP_MATCH = 0x05,
    LINE_PROTOCOL_OP_UNMATCH = 0x06,
    LINE_PROTOCOL_OP_ADD_FRIEND = 0x07,
} line_protocol_op;

typedef enum {
    LINE_PROTOCOL_STATUS_OK = 0x00,
    LINE_PROTOCOL_STATUS_FAIL = 0x01,
    LINE_PROTOCOL_STATUS_MORE = 0x02,
} line_protocol_status;

//common header
typedef union {
    struct {
        uint8_t magic;
        uint8_t op;
        uint8_t status;
        uint16_t client_id;
        //datalen = the length of complete header - the length of common header
        uint32_t datalen;
    } req;
    struct {
        uint8_t magic;
        uint8_t op;
        uint8_t status;
        uint16_t client_id;
        //datalen = the length of complete header - the length of common header
        uint32_t datalen;
    } res;
    uint8_t bytes[9];
} line_protocol_header;

//below are five types of complete header
//header used to login
typedef union {
    struct {
        line_protocol_header header;
        struct {
            uint8_t user[USER_LEN_MAX];
            char passwd[PASSWD_LEN_MAX];
            uint8_t passwd_hash[MD5_DIGEST_LENGTH];
        } body;
    } message;
    uint8_t bytes[sizeof(line_protocol_header) + MD5_DIGEST_LENGTH * 2];
} line_protocol_login;

typedef union {
    struct {
        line_protocol_header header;
        struct {
            char match_username[USER_LEN_MAX];
        } body;
    } message;
    uint8_t bytes[sizeof(line_protocol_header) + sizeof(char) * USER_LEN_MAX];
} line_protocol_match;

//header used to send meta data
typedef union {
    struct {
        line_protocol_header header;
        struct {
            //lenght of path of that file or directory under local repository
            uint32_t pathlen;
            //use lstat() to get file meta data
            struct stat stat;
            uint8_t hash[MD5_DIGEST_LENGTH];
        } body;
    } message;
    uint8_t bytes[sizeof(line_protocol_header) +
                    4 +
                    sizeof(struct stat) +
                    MD5_DIGEST_LENGTH];
} line_protocol_meta;

typedef union {
    struct {
        line_protocol_header header;
        struct {
            int is_msg;
            int first;
            int finished;
            int data_len;
            char data[DATA_LEN_MAX];
            char sender[FILE_LEN_MAX];
            char filename[FILE_LEN_MAX];
            char recv_user[USER_LEN_MAX];
        } body;
    } message;
    uint8_t bytes[sizeof(line_protocol_header) +
                    sizeof(int) * 4 +
                    sizeof(char) * (DATA_LEN_MAX + FILE_LEN_MAX*2 + USER_LEN_MAX)];
} line_protocol_msg_file;


//header used to send data of file
typedef union {
    struct {
        line_protocol_header header;
        struct {
            uint64_t datalen;
        } body;
    } message;
    uint8_t bytes[sizeof(line_protocol_header) + 8];
} line_protocol_file;

//header used to sync hard link
typedef union {
    struct {
        line_protocol_header header;
        struct {
            uint32_t srclen;
            uint32_t targetlen;
        } body;
    } message;
    uint8_t bytes[sizeof(line_protocol_header) + 8];
} line_protocol_hardlink;

//header used to delete file on server side
typedef union {
    struct {
        line_protocol_header header;
        struct {
            uint32_t pathlen;
        } body;
    } message;
    uint8_t bytes[sizeof(line_protocol_header) + 4];
} line_protocol_rm;

typedef struct {
    char match_name[USER_LEN_MAX];
    uint8_t status;
    uint8_t op;
} line_protocol_mes;

/*
 * utility
 */

// do md5 hash
void md5(const char* str, size_t len, uint8_t digest[MD5_DIGEST_LENGTH]);

// do file md5
int md5_file(const char* path, uint8_t digest[MD5_DIGEST_LENGTH]);

// recv message
int recv_message(int conn_fd, void* message, size_t len);

// copy header and recv remain part of message
int complete_message_with_header(
  int conn_fd, line_protocol_header* header, void* result);

// send message directly
int send_message(int conn_fd, void* message, size_t len);

// prepare all the detail for sending header and meta, then send message 
int send_message_to_server_or_client(int send_fd, int recv_fd, char *msg, int msg_len, char *recv_user, line_protocol_msg_file *req);

int send_file_to_server_or_client(int send_fd, int recv_fd, char *msg, int msg_len, char *recv_user, line_protocol_msg_file *req, int Is_first, int Is_finish, char *file_name);

int send_file_to_server_or_client_for_thread(int send_fd, int recv_fd, char *msg, int msg_len, char *recv_user, line_protocol_msg_file *req, int Is_first, int Is_finish, char *file_name);

int send_add_friend_req_to_server_or_client(int send_fd, int recv_fd, char *sending_user, char *recv_user, line_protocol_msg_file *req);

int send_log_req_to_server(int send_fd, int recv_fd, char *sending_user, char *recv_user, line_protocol_msg_file *req);

int send_log_to_client(int send_fd, int recv_fd, char *msg, int msg_len, char *recv_user, line_protocol_msg_file *req);

#ifdef __cplusplus
}
#endif

#endif
