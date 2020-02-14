#include "common.h"
#include "socktool.h"
#include <stdio.h>
#pragma comment(lib,  "ws2_32.lib") 

INT RecvAll(
	SOCKET s,
	CHAR* buf,
	INT len,
	INT flags)
{
	INT iSize, iResult;
	if (len <= 0) {
		DEBUG("RecvAll: invalid size: %d\n",
			len);
		return FALSE;
	}
	for (iSize = 0, iResult = 0;
		iSize < len;
		iSize += iResult) {
		iResult = recv(
			s,
			buf + iSize,
			len - iSize,
			flags);
		if (iResult <= 0) {
			DEBUG("RecvAll: error %d\n",
				WSAGetLastError());
			return FALSE;
		}
	}
	if (iSize != len) {
		DEBUG("RecvAll: size unmatched: %d <> %d\n",
			iSize, len);
		return FALSE;
	}
	return TRUE;
}

INT SendAll(
	SOCKET s,
	CHAR* buf,
	INT len,
	INT flags)
{
	INT iSize, iResult;
	if (len <= 0) {
		DEBUG("SendAll: invalid size: %d\n",
			len);
		return FALSE;
	}
	for (iSize = 0, iResult = 0;
		iSize < len;
		iSize += iResult) {
		iResult = send(
			s,
			buf + iSize,
			len - iSize,
			flags);
		if (iResult <= 0) {
			DEBUG("SendAll: error %d\n",
				WSAGetLastError());
			return FALSE;
		}
	}
	if (iSize != len) {
		DEBUG("SendAll: size unmatched: %d <> %d\n",
			iSize, len);
		return FALSE;
	}
	return TRUE;
}

INT RecvAll0(
	SOCKET s,
	CHAR* buf,
	INT bufsize,
	INT* len,
	INT flags)
{
	INT iZero = 0;
	INT iSize = 0;
	if (len) {
		*len = 0;
	}
	if (!RecvAll(
		s,
		(CHAR*)& iZero,
		sizeof(iZero),
		flags) || iZero) {
		DEBUG("recv zero failed with error: %d\n",
			WSAGetLastError());
		return FALSE;
	}
	if (!RecvAll(
		s,
		(CHAR*)& iSize,
		sizeof(iSize),
		flags) || bufsize < iSize) {
		DEBUG("recv size failed with error: %d\n",
			WSAGetLastError());
		return FALSE;
	}
	if (len) {
		*len = iSize;
	}
	if (!RecvAll(
		s,
		buf,
		iSize,
		flags)) {
		DEBUG("recv data failed with error: %d\n",
			WSAGetLastError());
		return FALSE;
	}

	return TRUE;
}

INT SendAll0(
	SOCKET s,
	CHAR* buf,
	INT len,
	INT flags)
{
	INT iZero = 0;
	INT iSize = len;
	if (!SendAll(
		s,
		(CHAR*)& iZero,
		sizeof(iZero),
		flags)) {
		DEBUG("send zero failed with error: %d\n",
			WSAGetLastError());
		return FALSE;
	}
	if (!SendAll(
		s,
		(CHAR*)& iSize,
		sizeof(iSize),
		flags)) {
		DEBUG("send size failed with error: %d\n",
			WSAGetLastError());
		return FALSE;
	}
	if (!SendAll(
		s,
		buf,
		len,
		flags)) {
		DEBUG("send data failed with error: %d\n",
			WSAGetLastError());
		return FALSE;
	}
	return TRUE;
}

SOCKET CreateSocket(
	CONST CHAR* pHost,
	CONST CHAR* pPort)
{
	SOCKET sock = INVALID_SOCKET;
	struct addrinfo* result = NULL,
		* ptr = NULL,
		hints;
	INT iResult;
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	DEBUG("getaddrinfo\n");
	// Resolve the server address and port
	iResult = getaddrinfo(
		pHost,
		pPort,
		&hints,
		&result);
	if (iResult != 0) {
		DEBUG("client: getaddrinfo failed with error: %d\n",
			iResult);
		return INVALID_SOCKET;
	}

	// Attempt to connect to an address until one succeeds
	for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
		sock = socket(
			ptr->ai_family,
			ptr->ai_socktype,
			ptr->ai_protocol);
		if (sock == INVALID_SOCKET) {
			DEBUG("client: socket failed with error: %ld\n",
				WSAGetLastError());
			return INVALID_SOCKET;
		}
		ULONG iMode = 1;
		iResult = ioctlsocket(
			sock,
			FIONBIO,
			&iMode);
		if (iResult != NO_ERROR)
		{
			printf("ioctlsocket failed with error: %ld\n",
				iResult);
		}
		iResult = connect(
			sock,
			ptr->ai_addr,
			(INT)ptr->ai_addrlen);
		struct timeval tv;
		fd_set readfds, writefds;
		tv.tv_sec = 0;
		tv.tv_usec = 100;
		FD_ZERO(&readfds);
		FD_SET(sock, &readfds);
		FD_ZERO(&writefds);
		FD_SET(sock, &writefds);
		if ((iResult = select(
			0,
			&readfds,
			&writefds,
			NULL,
			&tv)) == SOCKET_ERROR ||
			(!FD_ISSET(sock, &readfds) &&
				!FD_ISSET(sock, &writefds))) {
			DEBUG("select: fails: iResult: %d GetLastError(): %d\n",
				iResult, GetLastError());
			closesocket(sock);
			sock = INVALID_SOCKET;
			continue;
		}
		DEBUG("*** connect successfully\n");
		iMode = 0;
		iResult = ioctlsocket(
			sock,
			FIONBIO,
			&iMode);
		if (iResult != NO_ERROR)
		{
			printf("ioctlsocket failed with error: %ld\n",
				iResult);
		}
		break;
	}
	DEBUG("client: freeaddrinfo\n");
	freeaddrinfo(result);
	return sock;
}

INT EchoClient0(
	CHAR* pHost,
	CHAR* pPort,
	CHAR* pbSend,
	INT cbSend,
	CHAR* pbRecv,
	INT cbRecv,
	INT* pcbResult)
{
	DEBUG("enter EchoClient\n");
	printf("%s:%s\n", pHost, pPort);
	WSADATA wsaData;
	SOCKET ConnectSocket = INVALID_SOCKET;
	struct addrinfo* result = NULL,
		* ptr = NULL,
		hints;
	INT iResult;
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		DEBUG("client: WSAStartup failed with error: %d\n",
			iResult);
		return FALSE;
	}
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	DEBUG("getaddrinfo\n");
	iResult = getaddrinfo(
		pHost,
		pPort,
		&hints,
		&result);
	if (iResult != 0) {
		DEBUG("client: getaddrinfo failed with error: %d\n",
			iResult);
		WSACleanup();
		return FALSE;
	}

	for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
		ConnectSocket = socket(
			ptr->ai_family,
			ptr->ai_socktype,
			ptr->ai_protocol);
		if (ConnectSocket == INVALID_SOCKET) {
			DEBUG("client: socket failed with error: %ld\n",
				WSAGetLastError());
			WSACleanup();
			return FALSE;
		}
		iResult = connect(
			ConnectSocket,
			ptr->ai_addr,
			(int)ptr->ai_addrlen);
		if (iResult == SOCKET_ERROR) {
			closesocket(ConnectSocket);
			ConnectSocket = INVALID_SOCKET;
			continue;
		}
		break;
	}
	DEBUG("client: freeaddrinfo\n");
	freeaddrinfo(result);

	if (ConnectSocket == INVALID_SOCKET) {
		DEBUG("client: Unable to connect to server!\n");
		WSACleanup();
		return FALSE;
	}

	DEBUG("Client Send:\n");
	if (!SendAll0(
		ConnectSocket,
		pbSend,
		cbSend,
		0)) {
		DEBUG("client: send failed with error: %d\n",
			WSAGetLastError());
		closesocket(ConnectSocket);
		WSACleanup();
		return FALSE;
	}
	iResult = shutdown(ConnectSocket, SD_SEND);
	if (iResult == SOCKET_ERROR) {
		DEBUG("client: shutdown failed with error: %d\n",
			WSAGetLastError());
		closesocket(ConnectSocket);
		WSACleanup();
		return FALSE;
	}
	DEBUG("Client Recv:\n");
	if (!RecvAll0(ConnectSocket, pbRecv, cbRecv, pcbResult, 0)) {
		DEBUG("client: recv failed with error: %d\n",
			WSAGetLastError());
		closesocket(ConnectSocket);
		WSACleanup();
		return FALSE;
	}
	closesocket(ConnectSocket);
	WSACleanup();
	return TRUE;
}

BOOL GetLocalIP(CHAR* buf, INT buflen)
{
	WSADATA wsaData;
	SOCKET ConnectSocket = INVALID_SOCKET;
	struct addrinfo* result = NULL,
		* ptr = NULL,
		hints, *res;
	BOOL iResult;
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		DEBUG("client: WSAStartup failed with error: %d\n",
			iResult);
		return FALSE;
	}
	INT status;
	CHAR hostname[128];
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	gethostname(hostname, sizeof(hostname));
	if ((status = getaddrinfo(
		hostname,
		NULL,
		&hints,
		&res)) != 0) {
		DEBUG("getaddrinfo: %s\n",
			gai_strerror(status));
		return FALSE;
	}
	iResult = FALSE;
	buf[0] = 0;
	for (struct addrinfo* p = res; p != NULL; p = p->ai_next) {
		VOID* addr;
		CHAR ipver[100];
		if (p->ai_family == AF_INET) { // IPv4
			struct sockaddr_in* ipv4 =
				(struct sockaddr_in*)p->ai_addr;
			addr = &(ipv4->sin_addr);
			strcpy_s(ipver, 100, "IPv4");
			inet_ntop(p->ai_family, addr, buf, buflen);
			iResult = TRUE;
		}
		else { // IPv6
			struct sockaddr_in6* ipv6 =
				(struct sockaddr_in6*)p->ai_addr;
			addr = &(ipv6->sin6_addr);
			strcpy_s(ipver, 100, "IPv6");
		}
	}
	freeaddrinfo(res);
	WSACleanup();
	return iResult;
}

BOOL ScanIPSample()
{
	CHAR ip[32];
	INT i1, i2, i3, i4;
	GetLocalIP(ip, sizeof(ip));
	sscanf_s(ip, "%d.%d.%d.%d", &i1, &i2, &i3, &i4);
	for (INT i = 1; i < 255; i++) {
		if (i == i4) {
			continue;
		}
		sprintf_s(ip, sizeof(ip), "%d.%d.%d.%d", i1, i2, i3, i);
		printf("%s\n", ip);
	}
	return TRUE;
}

