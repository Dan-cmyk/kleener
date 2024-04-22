#ifndef COAP_SOCKET_MODEL
#define COAP_SOCKET_MODEL

#include <arpa/inet.h>
#include <klee/klee.h>
#include <memory.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

int CoAP_bind_model(int sockfd, const struct sockaddr *myaddr,
                    socklen_t addrlen);
ssize_t CoAP_sendto_model(int __fd, const void *__buf, size_t __n, int __flags,
                          const struct sockaddr *__addr, socklen_t __addr_len);
ssize_t CoAP_recvfrom_model(int __fd, void *__buf, size_t __n, int __flags,
                            struct sockaddr *__addr, socklen_t *__addr_len);

#endif