#ifndef _CSIEBOX_SERVER_
#define _CSIEBOX_SERVER_

#ifdef __cplusplus
extern "C" {
#endif

#include "common.h"

#include <limits.h>
#include <time.h>

#define MAX_CLIENT 100

typedef struct {
  char user[USER_LEN_MAX];
  char passwd_hash[MD5_DIGEST_LENGTH];
} line_account_info;

typedef struct {
  line_account_info account;
  int conn_fd;
  char match_username[USER_LEN_MAX];
} line_client_info;

typedef struct {
  struct {
    char path[PATH_MAX];
    char account_path[PATH_MAX];
  } arg;
  int listen_fd;
  line_client_info** client;
} line_server;

typedef struct {
    line_server *server;
    int conn_fd; 
} line_server_thread_args;

typedef struct {
    int total_message;
    char message[TOTAL_MSG_MAX][DATA_LEN_MAX];
} message_container;

typedef struct {
    int Is_sender;
    int Is_msg;
    char message[MESSAGE_LEN_MAX];
    char time[11];
} message_buf;

void line_server_init(line_server** server, int argc, char** argv);
int line_server_run(line_server* server);
void line_server_destroy(line_server** server);

#ifdef __cplusplus
}
#endif

#endif
