#define _GNU_SOURCE

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include <string.h> 
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <err.h>
#include <errno.h>
#include "marshall.h"

// The following line declares a function pointer with the same prototype as the open function.  
int (*orig_open)(const char *pathname, int flags, ...);  // mode_t mode is needed when flags includes O_CREAT
int (*orig_close)(int fd);
ssize_t (*orig_read)(int fd, void *buf, size_t count); 
ssize_t (*orig_write)(int fd, const void *buf, size_t count);
off_t (*orig_lseek)(int fd, off_t offset, int whence);
int (*orig_stat)(int ver, const char *pathname, struct stat *statbuf);
int (*orig_unlink)(const char *pathname);
ssize_t (*orig_getdirentries)(int fd, char *buf, size_t nbytes , off_t *basep);
struct dirtreenode* (*orig_getdirtree)(const char *path);
void (*orig_freedirtree)(struct dirtreenode* dt);

int sockfd = -1;

void send_recv_msg(general_wrapper *msg_sent, void *msg_recv, int recv_len) {
	char *serverip;
	char *serverport;
	unsigned short port;
	int rv;
	struct sockaddr_in srv;

	// Get environment variable indicating the ip address of the server
	serverip = getenv("server15440");
	if (!serverip)  {
		serverip = "127.0.0.1";
	}
	
	// Get environment variable indicating the port of the server
	serverport = getenv("serverport15440");
	if (!serverport) {
		serverport = "15440";
	}
	port = (unsigned short)atoi(serverport);

	if (sockfd<0) {
		sockfd = socket(AF_INET, SOCK_STREAM, 0); // TCP/IP socket
		
		// setup address structure to point to server
		memset(&srv, 0, sizeof(srv));			// clear it first
		srv.sin_family = AF_INET;			// IP family
		srv.sin_addr.s_addr = inet_addr(serverip);	// IP address of server
		srv.sin_port = htons(port);			// server port

		// actually connect to the server
		rv = connect(sockfd, (struct sockaddr*)&srv, sizeof(struct sockaddr));
		if (rv<0) err(1,0);
	}
	
	
	// Send message to server
	fprintf(stderr, "Send message to server...\n");
	send(sockfd, msg_sent, msg_sent->total_len, 0);	// send message; should check return value

	fprintf(stderr, "Get message From server...\n");
	rv = recv(sockfd, msg_recv, recv_len, 0);	// get message
	if (rv<0) err(1,0);			// in case something went wrong
	fprintf(stderr, "Message Received...\n");
	// rec[rv]=0;				// null terminate string to print
}

// This is our replacement for the open function from libc.
int open(const char *pathname, int flags, ...) {
	mode_t m=0;
	if (flags & O_CREAT) {
		va_list a;
		va_start(a, flags);
		m = va_arg(a, mode_t);
		va_end(a);
	}
	// Marshall data [int total_length, int op_code, int flags, int path_len, mode_t mode, char path[0]]
	int path_length = strlen(pathname) + 1;
	int total_length = sizeof(general_wrapper) + 
						sizeof(open_payload) + path_length;
	general_wrapper *header = (general_wrapper *)malloc(total_length); 
	header->total_len = total_length;
	header->op_code = OPEN;
	open_payload *open_data = (open_payload *)header->payload;
	open_data->flags = flags;
	open_data->mode = m;
	open_data->path_len = path_length;
	memcpy(open_data->path, pathname, path_length);
	fprintf(stderr, "flags: %d\n", flags);
    fprintf(stderr, "mode: %d\n", m);
	fprintf(stderr, "path_len: %d\n", open_data->path_len);
    fprintf(stderr, "path: %s\n", open_data->path);
	fprintf(stderr, "mode_t size: %ld\n", sizeof(mode_t));

	// Send and receive data
	void *msg_recv = malloc(2 * sizeof(int));
	send_recv_msg(header, msg_recv, 2 * sizeof(int));

	// Receive information [int fd, int err] from server
	int rec_fd = *((int *)msg_recv);
	int rec_err = *((int *)msg_recv + 1);
	if (rec_fd < 0 || rec_err != 0) {
		errno = rec_err;
		perror("Open error");
	}
	free(header);
	free(msg_recv);

	return rec_fd;
}

int close(int fd) {
	fprintf(stderr, "mylib: close\n");
	// Marshall data
	int total_length = sizeof(general_wrapper) + sizeof(close_payload); 
	general_wrapper *header = (general_wrapper *)malloc(total_length); 
	header->total_len = total_length;
	header->op_code = CLOSE;
	close_payload *close_data = (close_payload *)header->payload;
	close_data->filedes = fd;
	fprintf(stderr, "fd: %d\n", close_data->filedes);

	// Send and receive data
	void *msg_recv = malloc(2 * sizeof(int));
	send_recv_msg(header, msg_recv, 2 * sizeof(int));

	// Receive information [int fd, int err] from server
	int rec_fd = *((int *)msg_recv);
	int rec_err = *((int *)msg_recv + 1);
	if (rec_fd < 0 || rec_err != 0) {
		errno = rec_err;
		perror("Close error");
	}
	free(header);
	free(msg_recv);

	return rec_fd;
}

ssize_t read(int fd, void *buf, size_t count) {
	fprintf(stderr, "mylib: read\n");
	// Marshall data [int total_length, int op_code, int fildes, size_t nbytes] 
	// In read, no need to send buf, we only need to receive what is read from the 
	// server side. 
	int total_length = sizeof(general_wrapper) + 
						sizeof(read_write_payload);
	general_wrapper *header = (general_wrapper *)malloc(total_length); 
	header->total_len = total_length;
	header->op_code = READ;
	read_write_payload *read_data = (read_write_payload *)header->payload;
	read_data->fildes = fd;
	read_data->nbyte = count;
	fprintf(stderr, "fildes: %d\n", read_data->fildes);
	fprintf(stderr, "nbytes : %d\n", (int)read_data->nbyte);
	
	// Send and receive data
	void *msg_recv = malloc(sizeof(ssize_t) + sizeof(int) + count);
	fprintf(stderr, "do send_recv_msg()\n");
	send_recv_msg(header, msg_recv, sizeof(ssize_t) + sizeof(int) + count);

	// Receive information [ssize_t rec_sz, int err] from server
	ssize_t rec_sz = *((ssize_t *)msg_recv);
	int rec_err = *(int *)(msg_recv + sizeof(ssize_t));
	memcpy(buf, msg_recv + sizeof(int) + sizeof(ssize_t), count);

	if (rec_sz < 0 || rec_err != 0) {
		errno = rec_err;
		perror("Read error");
	}
	free(header);
	free(msg_recv);

	fprintf(stderr, "Read size: %ld\n", rec_sz); 
	return rec_sz;
}

ssize_t write(int fd, const void *buf, size_t count) {
	fprintf(stderr, "mylib: write\n");
	// Marshall data [int total_length, int op_code, int fildes, size_t nbytes, char buf[0]]
	int total_length = sizeof(general_wrapper) + 
						sizeof(read_write_payload) + count;
	general_wrapper *header = (general_wrapper *)malloc(total_length); 
	header->total_len = total_length;
	header->op_code = WRITE;
	read_write_payload *write_data = (read_write_payload *)header->payload;
	write_data->fildes = fd;
	write_data->nbyte = count;
	memcpy(write_data->buf, buf, count);
	fprintf(stderr, "fildes: %d\n", write_data->fildes);
	fprintf(stderr, "nbytes : %d\n", (int)write_data->nbyte);
	
	// Send and receive data
	void *msg_recv = malloc(sizeof(ssize_t) + sizeof(int));
	fprintf(stderr, "do send_recv_msg()\n");
	send_recv_msg(header, msg_recv, sizeof(ssize_t) + sizeof(int));

	// Receive information [ssize_t rec_sz, int err] from server
	ssize_t rec_sz = *((ssize_t *)msg_recv);
	int rec_err = *(int *)(msg_recv + sizeof(ssize_t));
	if (rec_sz < 0 || rec_err != 0) {
		errno = rec_err;
		perror("Write error");
	}
	free(header);
	free(msg_recv);

	fprintf(stderr, "Written size: %ld\n", rec_sz); 
	return rec_sz;
}

off_t lseek(int fd, off_t offset, int whence) {
	fprintf(stderr, "mylib: lseek\n");
	int total_length = sizeof(general_wrapper) + sizeof(lseek_payload);
	general_wrapper *header = (general_wrapper *)malloc(total_length); 
	header->total_len = total_length;
	header->op_code = LSEEK;
	lseek_payload *lseek_data = (lseek_payload *)header->payload;
	lseek_data->fd = fd;
	lseek_data->offset = offset;
	lseek_data->whence = whence;

	fprintf(stderr, "fd: %d\n", lseek_data->fd);
	fprintf(stderr, "offset : %ld\n", lseek_data->offset);
	fprintf(stderr, "whence : %d\n", lseek_data->whence);
	// Send and receive data
	void *msg_recv = malloc(sizeof(off_t) + sizeof(int));
	fprintf(stderr, "fuck\n");
	send_recv_msg(header, msg_recv, sizeof(off_t) + sizeof(int));

	// Receive information [int fd, int err] from server
	off_t rec_loc = *((off_t *)msg_recv);
	int rec_err = *(int *)(msg_recv + sizeof(off_t));
	if (rec_loc < 0 || rec_err != 0) {
		errno = rec_err;
		perror("Lseek error");
	}
	free(header);
	free(msg_recv);

	return rec_loc;
}

int __xstat(int ver, const char *pathname, struct stat *statbuf) {
	fprintf(stderr, "mylib: __xstat\n");
	int path_length = strlen(pathname) + 1;
	int total_length = sizeof(general_wrapper) + 
						sizeof(stat_payload) + path_length;
	general_wrapper *header = (general_wrapper *)malloc(total_length); 
	header->total_len = total_length;
	header->op_code = STAT;
	stat_payload *stat_data = (stat_payload *)header->payload;
	stat_data->ver = ver;
	stat_data->statbuf = *statbuf;
	stat_data->path_len = path_length;
	memcpy(stat_data->pathname, pathname, path_length);

	fprintf(stderr, "ver: %d\n", stat_data->ver);
	fprintf(stderr, "path_len: %d\n", stat_data->path_len);
    fprintf(stderr, "path: %s\n", stat_data->pathname);

	// Send and receive data
	void *msg_recv = malloc(2 * sizeof(int));
	send_recv_msg(header, msg_recv, 2 * sizeof(int));

	// Receive information [int fd, int err] from server
	int rec_fd = *((int *)msg_recv);
	int rec_err = *((int *)msg_recv + 1);
	if (rec_fd < 0 || rec_err != 0) {
		errno = rec_err;
		perror("__xstat error");
	}
	free(header);
	free(msg_recv);

	return rec_fd;
}

int unlink(const char *pathname) {
	// send_msg("unlink\n");
	fprintf(stderr, "mylib: unlink\n");
	int path_length = strlen(pathname) + 1;
	int total_length = sizeof(general_wrapper) + 
						sizeof(unlink_payload) + path_length;
	general_wrapper *header = (general_wrapper *)malloc(total_length); 
	header->total_len = total_length;
	header->op_code = UNLINK;
	unlink_payload *unlink_data = (unlink_payload *)header->payload;
	unlink_data->path_len = path_length;
	memcpy(unlink_data->pathname, pathname, path_length);

	fprintf(stderr, "path_len: %d\n", unlink_data->path_len);
    fprintf(stderr, "path: %s\n", unlink_data->pathname);

	// Send and receive data
	void *msg_recv = malloc(2 * sizeof(int));
	send_recv_msg(header, msg_recv, 2 * sizeof(int));

	// Receive information [int fd, int err] from server
	int rec_fd = *((int *)msg_recv);
	int rec_err = *((int *)msg_recv + 1);
	if (rec_fd < 0 || rec_err != 0) {
		errno = rec_err;
		perror("unlink error");
	}
	free(header);
	free(msg_recv);

	return rec_fd;
}

ssize_t getdirentries(int fd, char *buf, size_t nbytes , off_t *basep) {
	// send_msg("getdirentries\n");
	fprintf(stderr, "mylib: getdirentries\n");
	return orig_getdirentries(fd, buf, nbytes, basep);
}

struct dirtreenode* getdirtree(const char *path) {
	// send_msg("getdirtree\n");
	fprintf(stderr, "mylib: getdirtree\n");
	return orig_getdirtree(path);
}

void freedirtree(struct dirtreenode* dt) {
	// send_msg("freedirtree\n");
	fprintf(stderr, "mylib: freedirtree\n");
	return orig_freedirtree(dt);
}

// This function is automatically called when program is started
void _init(void) {
	// Set function pointer orig_open to point to the original open function
	orig_open = dlsym(RTLD_NEXT, "open");
	orig_close = dlsym(RTLD_NEXT, "close");
	orig_read = dlsym(RTLD_NEXT, "read");
	orig_write = dlsym(RTLD_NEXT, "write");
	orig_lseek = dlsym(RTLD_NEXT, "lseek");
	orig_stat = dlsym(RTLD_NEXT, "__xstat");	
	orig_unlink = dlsym(RTLD_NEXT, "unlink");
	orig_getdirentries = dlsym(RTLD_NEXT, "getdirentries");
	orig_getdirtree  = dlsym(RTLD_NEXT, "getdirtree");
	orig_freedirtree = dlsym(RTLD_NEXT, "freedirtree");
	fprintf(stderr, "Init mylib\n");
}

void _fini(void) {
	fprintf(stderr, "sockfd: %d\n", sockfd);
	orig_close(sockfd);
}


