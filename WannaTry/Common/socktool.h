#pragma once

#ifndef SOCKET
#include <WinSock2.h>
#include <WS2tcpip.h>
#endif

#ifndef DEFAULT_BUFLEN
#define DEFAULT_BUFLEN 4096
#endif

INT RecvAll(SOCKET, CHAR*, INT, INT);
INT SendAll(SOCKET, CHAR*, INT, INT);
INT RecvAll0(SOCKET, CHAR*, INT, INT*, INT);
INT SendAll0(SOCKET, CHAR*, INT, INT);
SOCKET CreateSocket(CONST CHAR*, CONST CHAR*);
INT EchoClient0(CHAR*, CHAR*, CHAR*, INT, CHAR*, INT, INT *);
BOOL GetLocalIP(CHAR*, INT);
BOOL ScanIPSample();
