#include <sys/types.h>

// The operation code name for functions
#define OPEN 0
#define CLOSE 1
#define WRITE 2

typedef struct general_wrapper {
    int total_len;
    int op_code;
    char payload[0];
} general_wrapper;

typedef struct open_payload {
    int flags;
    int path_len;
    mode_t mode;
    char path[0];
} open_payload;

typedef struct close_payload {
    int filedes;
} close_payload;

typedef struct write_payload {
    int fildes;
    size_t nbyte;
    char buf[0];
} write_payload;
