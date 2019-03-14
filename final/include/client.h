#ifndef _LINE_CLIENT_
#define _LINE_CLIENT_

#ifdef __cplusplus
extern "C" {
#endif

#include "common.h"

#include <limits.h>

typedef struct {
  struct {
    char name[30];
    char server[30];
    char user[USER_LEN_MAX];
    char passwd[PASSWD_LEN_MAX];
    char path[PATH_MAX];
  } arg;
  int Is_register;
  int conn_fd;
  int client_id;
} line_client;

typedef struct {
    int conn_fd;
    int recv_res_fd;
    char *sending_user;
    char *recv_user;
} thread_args_interface;

typedef struct {
    int conn_fd;
    int send_res_fd;
    char *username;
} thread_args_handle;

typedef struct {
    pthread_t tid;
    int conn_fd;
    int recv_res_fd;
    char file_name[FILE_NAME_MAX];
    char *sending_user;
    char *recv_user;
} thread_args_send_file;

void line_client_init(line_client** client, int argc, char** argv);
int line_client_run(line_client* client);
void line_client_destroy(line_client** client);

#ifdef __cplusplus
}
#endif

#endif
