#include "client.h"
int main(int argc, char** argv) {
    line_client* box = 0;
    line_client_init(&box, argc, argv);
    if (box) {
        line_client_run(box);
    }
    line_client_destroy(&box);
    return 0;
}