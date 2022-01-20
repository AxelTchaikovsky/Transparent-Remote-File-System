#define _GNU_SOURCE

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

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

void send_msg(char *msg) {
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
		fprintf(stderr, "Environment variable serverport15440 not found.  Using 15440\n");
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
	
	
	// send message to server
	send(sockfd, msg, strlen(msg), 0);	// send message; should check return value
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
	// we just print a message, then call through to the original open function (from libc)
	send_msg("open\n");
	fprintf(stderr, "mylib: open called for path %s\n", pathname);
	return orig_open(pathname, flags, m);
}

int close(int fd) {
	send_msg("close\n");
	fprintf(stderr, "mylib: close\n");
	return orig_close(fd);
}

ssize_t read(int fd, void *buf, size_t count) {
	send_msg("read\n");
	fprintf(stderr, "mylib: read\n");
	return orig_read(fd, buf, count);
}

ssize_t write(int fd, const void *buf, size_t count) {
	send_msg("write\n");
	fprintf(stderr, "mylib: write\n");
	return orig_write(fd, buf, count);
}

off_t lseek(int fd, off_t offset, int whence) {
	send_msg("lseek\n");
	fprintf(stderr, "mylib: lseek\n");
	return orig_lseek(fd, offset, whence);
}

int __xstat(int ver, const char *pathname, struct stat *statbuf) {
	send_msg("__xstat\n");
	fprintf(stderr, "mylib: __xstat\n");
	return orig_stat(ver, pathname, statbuf);
}

int unlink(const char *pathname) {
	send_msg("unlink\n");
	fprintf(stderr, "mylib: unlink\n");
	return orig_unlink(pathname);
}

ssize_t getdirentries(int fd, char *buf, size_t nbytes , off_t *basep) {
	send_msg("getdirentries\n");
	fprintf(stderr, "mylib: getdirentries\n");
	return orig_getdirentries(fd, buf, nbytes, basep);
}

struct dirtreenode* getdirtree(const char *path) {
	send_msg("getdirtree\n");
	fprintf(stderr, "mylib: getdirtree\n");
	return orig_getdirtree(path);
}

void freedirtree(struct dirtreenode* dt) {
	send_msg("freedirtree\n");
	fprintf(stderr, "mylib: freedirtree\n");
	return orig_freedirtree(dt);
}

// This function is automatically called when program is started
void _init(void) {
	// set function pointer orig_open to point to the original open function
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




