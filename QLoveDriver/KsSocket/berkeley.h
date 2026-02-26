#pragma once

#ifdef __cplusplus
extern "C" {
#endif


#include<ntifs.h>
#include<windef.h>
#include<ntddk.h>
#include<wdm.h>	
#include <wsk.h>

#include "ksocket.h"

	typedef int       socklen_t;
	typedef intptr_t  ssize_t;


	typedef int SOCKET;

#define INVALID_SOCKET (SOCKET)(-1)
#define SOCKET_ERROR -1

	typedef __int8 int8_t;
	typedef __int16 int16_t;
	typedef __int32 int32_t;
	typedef __int64 int64_t;

	typedef unsigned __int8 uint8_t;
	typedef unsigned __int16 uint16_t;
	typedef unsigned __int32 uint32_t;
	typedef unsigned __int64 uint64_t;

	//typedef uint8_t bool;


	uint32_t htonl(uint32_t hostlong);
	uint16_t htons(uint16_t hostshort);
	uint32_t ntohl(uint32_t netlong);
	uint16_t ntohs(uint16_t netshort);

	int getaddrinfo(const char* node, const char* service, const struct addrinfo* hints, struct addrinfo** res);
	void freeaddrinfo(struct addrinfo* res);

	int socket_connection(int domain, int type, int protocol);
	int socket_listen(int domain, int type, int protocol);
	int socket_datagram(int domain, int type, int protocol);


	int connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen);
	int listen(int sockfd, int backlog);
	int bind(int sockfd, const struct sockaddr* addr, socklen_t addrlen);
	int accept(int sockfd, struct sockaddr* addr, socklen_t* addrlen);
	int send(int sockfd, const void* buf, size_t len, int flags);

	int sendfast(int sockfd, WSK_BUF* Buffer, int flags);

	int sendto(int sockfd, const void* buf, size_t len, int flags, const struct sockaddr* dest_addr, socklen_t addrlen);
	int recvfast(int sockfd, WSK_BUF* Buffer, int flags);
	int recv(int sockfd, void* buf, size_t len, int flags);
	int recvfrom(int sockfd, void* buf, size_t len, int flags, struct sockaddr* src_addr, socklen_t* addrlen);
	int closesocket(int sockfd);

	//NTSTATUS GetLastError();

#define socket  socket_connection

#ifdef __cplusplus
}
#endif