#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include "marshall.h"

#define MAXMSGLEN 100
#define OFFSET 800

int sessfd = -1;

void do_open(void *open_data, int len);
void do_close(void *close_data, int len); 
void do_write(void *write_data, int len);
void do_read(void *read_data, int len); 
void do_stat(void *stat_data, int len); 
void do_lseek(void *lseek_data, int len);
void do_unlink(void *unlink_data, int len);

int main(int argc, char**argv) {
	char buf[MAXMSGLEN+1];
	char *serverport;
	unsigned short port;
	int sockfd, rv;
	struct sockaddr_in srv, cli;
	socklen_t sa_size;
	
	// Get environment variable indicating the port of the server
	serverport = getenv("serverport15440");
	if (serverport) port = (unsigned short)atoi(serverport);
	else port=15440;
	
	// Create socket
	sockfd = socket(AF_INET, SOCK_STREAM, 0);	// TCP/IP socket
	if (sockfd<0) err(1, 0);			// in case of error
	
	// setup address structure to indicate server port
	memset(&srv, 0, sizeof(srv));			// clear it first
	srv.sin_family = AF_INET;			// IP family
	srv.sin_addr.s_addr = htonl(INADDR_ANY);	// don't care IP address
	srv.sin_port = htons(port);			// server port

	// bind to our port
	rv = bind(sockfd, (struct sockaddr*)&srv, sizeof(struct sockaddr));
	if (rv<0) err(1,0);
	
	// start listening for connections
	rv = listen(sockfd, 5);
	if (rv<0) err(1,0);

	// main server loop
	while (1) {
        // wait for next client, get session socket
	    sa_size = sizeof(struct sockaddr_in);
	    sessfd = accept(sockfd, (struct sockaddr *)&cli, &sa_size);
	    fprintf(stderr, "-----Setting up session %d-----\n", sessfd); 
        if (sessfd < 0) {
            err(1,0);
            continue;
        }
        
        while (1) {
            int loop_cnt = 0, read = 0, total_length = 0; 
            int op_code = -1;
            general_wrapper *pkg = NULL;
            
            // get messages and send replies to this client, until it goes away
            while ((rv = recv(sessfd, buf, MAXMSGLEN, 0)) > 0) {
                fprintf(stderr, "rv: %d\n", rv);
                if (loop_cnt == 0) {
                    total_length = *(int *)buf;
                    fprintf(stderr, "total length : %d\n", total_length);
                    pkg = malloc(total_length);
                    memcpy((void *)pkg, buf, rv);
                    fprintf(stderr, "buf_cont: %s\n", buf);
                    read += rv;
                    loop_cnt++;
                } else {
                    memcpy((void *)pkg + read, buf, rv);
                    fprintf(stderr, "buf_cont: %s\n", buf);
                    read += rv;
                }
                if (read >= total_length) { 
                    op_code = pkg->op_code;
                    fprintf(stderr, "Server got message...\n"); 
                    break; 
                }
            }

            switch (op_code) {
            case OPEN:
                do_open(pkg->payload, total_length - 2 * sizeof(int));
                break;
            case CLOSE:
                do_close(pkg->payload, total_length - 2 * sizeof(int));
                break;
            case WRITE:
                do_write(pkg->payload, total_length - 2 * sizeof(int));
                break;
            case READ:
                do_read(pkg->payload, total_length - 2 * sizeof(int));
                break;
            case LSEEK:
                do_lseek(pkg->payload, total_length - 2 * sizeof(int));
                break;
            case STAT:
                do_stat(pkg->payload, total_length - 2 * sizeof(int));
                break;
            case UNLINK:
                do_unlink(pkg->payload, total_length - 2 * sizeof(int));
                break;
            default:
                fprintf(stderr, "Default...\n");
                break;
            }
            free(pkg);
            if (rv<0) err(1,0);
            if (op_code == -1) {
                break;
            }
        }
        close(sessfd);
        fprintf(stderr, "-----Close session %d-----\n", sessfd);
	}
	// close socket
	close(sockfd);
	return 0;
}

void do_open(void *open_data, int len) {
    fprintf(stderr, "mylib: open\n");
    open_payload *data = (open_payload *)malloc(len);
    memcpy(data, open_data, len);

    // Data [int total_length, int op_code, int flags, mode_t mode, char *pathname]
    int flags = data->flags;
    mode_t mode = data->mode;
    char *path = (char *)malloc(data->path_len);
    memcpy(path, data->path, data->path_len);
    path[data->path_len] = 0;

    fprintf(stderr, "flags: %d\n", flags);
    fprintf(stderr, "mode: %d\n", mode);
    fprintf(stderr, "path_len: %d\n", data->path_len);
    fprintf(stderr, "path: %s\n", path);

    // Call open()
    int fd = -1;
    if (flags & O_CREAT) {
        fd = open(path, flags, mode);
    } else {
        fd = open(path, flags);
    }

    // Send message to client
    if (fd >= 0) {
        fd += OFFSET;
    }
    void *pkg = malloc(2 * sizeof(int));
    memcpy(pkg, &fd, sizeof(int));
    memcpy(pkg + sizeof(int), &errno, sizeof(int));
    send(sessfd, pkg, 2 * sizeof(int), 0);
    free(pkg);
    free(data);
}

void do_close(void *close_data, int len) {
    fprintf(stderr, "mylib: close\n");
    close_payload *data = (close_payload *)malloc(len);
    memcpy(data, close_data, len);
    // Data 
    fprintf(stderr, "filedes: %d\n", data->filedes - OFFSET);

    // Call close()
    int fd = close(data->filedes - OFFSET);

    // Send message to client
    void *pkg = malloc(2 * sizeof(int));
    memcpy(pkg, &fd, sizeof(int));
    memcpy(pkg + sizeof(int), &errno, sizeof(int));
    send(sessfd, pkg, 2 * sizeof(int), 0);
    free(pkg);
    free(data);
}

void do_read(void *read_data, int len) {
    fprintf(stderr, "mylib: read\n");
    read_write_payload *data = (read_write_payload *)malloc(len);
    memcpy(data, read_data, len);
    // Data 
    fprintf(stderr, "filedes: %d\n", data->fildes - OFFSET);
    void *pkg = malloc(sizeof(ssize_t) + sizeof(int) + data->nbyte);

    // Call read()
    ssize_t sz = read(data->fildes - OFFSET, 
                        pkg + sizeof(ssize_t) + sizeof(int), data->nbyte);
    fprintf(stderr, "Read size: %ld\n", sz);
    fprintf(stderr, "buf: %s\n", (char *)(pkg + sizeof(ssize_t) + sizeof(int)));
    perror("Server read");
    
    // Send message to client
    memcpy(pkg, &sz, sizeof(ssize_t));
    memcpy(pkg + sizeof(ssize_t), &errno, sizeof(int));
    send(sessfd, pkg, sizeof(ssize_t) + sizeof(int) + data->nbyte, 0);
    free(pkg);
    free(data);
}


void do_write(void *write_data, int len) {
    fprintf(stderr, "mylib: write\n");
    read_write_payload *data = (read_write_payload *)malloc(len);
    memcpy(data, write_data, len);
    // Data 
    fprintf(stderr, "filedes: %d\n", data->fildes - OFFSET);
    fprintf(stderr, "buf: %s\n", data->buf);

    // Call write()
    ssize_t sz = write(data->fildes - OFFSET, data->buf, data->nbyte);
    fprintf(stderr, "Written size: %ld\n", sz);
    perror("Server write");

    // Send message to client
    void *pkg = malloc(sizeof(int) + sizeof(ssize_t));
    memcpy(pkg, &sz, sizeof(ssize_t));
    memcpy(pkg + sizeof(ssize_t), &errno, sizeof(int));
    send(sessfd, pkg, sizeof(int) + sizeof(ssize_t), 0);
    free(pkg);
    free(data);
}

void do_lseek(void *lseek_data, int len) {
    fprintf(stderr, "mylib: lseek\n");
    lseek_payload *data = (lseek_payload *)malloc(len);
    memcpy(data, lseek_data, len);
    
    fprintf(stderr, "fd: %d\n", data->fd - OFFSET);
	fprintf(stderr, "offset : %ld\n", data->offset);
	fprintf(stderr, "whence : %d\n", data->whence);

    // Call lseek()
    off_t loc = lseek(data->fd - OFFSET, data->offset, data->whence);

    // Send message to client
    void *pkg = malloc(sizeof(off_t) + sizeof(int));
    memcpy(pkg, &loc, sizeof(off_t));
    memcpy(pkg + sizeof(off_t), &errno, sizeof(int));
    send(sessfd, pkg, sizeof(off_t) + sizeof(int), 0);
    free(pkg);
    free(data);
}

void do_stat(void *stat_data, int len) {
    fprintf(stderr, "mylib: stat\n");
    stat_payload *data = (stat_payload *)malloc(len);
    memcpy(data, stat_data, len);

    int ver = data->ver;
    struct stat *statbuf = &data->statbuf;
    char *path = (char *)malloc(data->path_len);
    memcpy(path, data->pathname, data->path_len);
    path[data->path_len] = 0;

    fprintf(stderr, "ver: %d\n", data->ver);
    fprintf(stderr, "path_len: %d\n", data->path_len);
    fprintf(stderr, "path: %s\n", path);

    // Call __xstat()
    int ret = __xstat(ver, data->pathname, statbuf);

    // Send message to client
    void *pkg = malloc(2 * sizeof(int));
    memcpy(pkg, &ret, sizeof(int));
    memcpy(pkg + sizeof(int), &errno, sizeof(int));
    send(sessfd, pkg, 2 * sizeof(int), 0);
    free(pkg);
    free(data);
}

void do_unlink(void *unlink_data, int len) {
    fprintf(stderr, "mylib: unlink\n");
    unlink_payload *data = (unlink_payload *)malloc(len);
    memcpy(data, unlink_data, len);

    char *path = (char *)malloc(data->path_len);
    memcpy(path, data->pathname, data->path_len);
    path[data->path_len] = 0;

    fprintf(stderr, "path_len: %d\n", data->path_len);
    fprintf(stderr, "path: %s\n", path);

    // Call unlink()
    int ret = unlink(data->pathname);

    // Send message to client
    void *pkg = malloc(2 * sizeof(int));
    memcpy(pkg, &ret, sizeof(int));
    memcpy(pkg + sizeof(int), &errno, sizeof(int));
    send(sessfd, pkg, 2 * sizeof(int), 0);
    free(pkg);
    free(data);
}
