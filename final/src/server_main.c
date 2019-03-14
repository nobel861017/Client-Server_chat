#include "server.h"
int main(int argc, char** argv) {
    line_server* box = 0;
    line_server_init(&box, argc, argv);
    if (box) {
        line_server_run(box);
    }
    line_server_destroy(&box);
    return 0;
}