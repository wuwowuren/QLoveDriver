#pragma once

#include "KsSocket/berkeley.h"



typedef struct _SOCKET_BUFFER {
	char* BufferRecv;
	char* BufferSend;
	WSK_BUF RecvBuF;
	WSK_BUF SendBuF;
}SOCKET_BUFFER;

#define RECV_SIZE 0x8000
#define SEND_SIZE 0x100000

//STATUS_SUCCESS

typedef int (*hBuffer)(SOCKET s, char* pBuffer, uint32_t nLen);

typedef int (*hBufferUdp)(SOCKET s, char* pBuffer, uint32_t nLen, struct sockaddr* Addr, int Len);

BOOLEAN KServer_Start(int Port, hBuffer _CALLBACK);

BOOLEAN KServer_StartSign(DWORD RandSign, hBuffer CALL);

BOOLEAN KServer_StartUdp(int port, hBufferUdp CALL);
