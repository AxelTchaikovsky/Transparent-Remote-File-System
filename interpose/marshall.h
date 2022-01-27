#include <sys/types.h>

// The operation code name for functions
#define OPEN 0
#define CLOSE 1
#define WRITE 2
#define READ 3
#define LSEEK 4
#define STAT 5
#define UNLINK 6
#define GETDIRENTRIES 7

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

typedef struct read_write_payload {
    int fildes;
    size_t nbyte;
    char buf[0];
} read_write_payload;

typedef struct lseek_payload {
    int fd;
    off_t offset;
    int whence;
} lseek_payload;

typedef struct stat_payload {
    int ver;
    int path_len;
    struct stat statbuf;
    char pathname[0];
} stat_payload;

typedef struct unlink_payload {
    int path_len;
    char pathname[0];
} unlink_payload; 

typedef struct getdirentries_payload {
    int fd;
    size_t nbyte;
    off_t basep;
} getdirentries_payload; 
