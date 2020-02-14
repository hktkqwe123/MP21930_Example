// EZCrypt.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <stdio.h>
#include <tchar.h>
#include "EZHybrid.h"
#include "../Common/common.h"
#include "../Common/hexdump.h"
#include "../EZCrypt/Keys.h"


int main()
{
	TCHAR filename1[] = _T("D:\\TESTDATA\\test.txt");
	TCHAR filename2[] = _T("D:\\TESTDATA\\test.txt.WNCRY");
	PEZHybrid pHybrid;
	if (0) {
		printf("debug0\n");
		pHybrid = new EZHybrid();
		printf("debug1\n");
		pHybrid->ImportPublicKey(WannaPublicKey, WannaPublicKeySize());
		printf("debug2\n");
		pHybrid->Encrypt(filename1);
		delete pHybrid;
		return 0;
	}
	if (1) {
		pHybrid = new EZHybrid();
		printf("debug3\n");
		if (GetFileAttributes(filename2) != INVALID_FILE_ATTRIBUTES) {
			pHybrid->ImportPrivateKey(WannaPrivateKey, WannaPrivateKeySize());
			printf("debug3-1\n");
			pHybrid->Decrypt(filename2);
		}
		else {
			printf("encrypted file not found\n");
		}
		printf("debug4\n");
		delete pHybrid;
	}
	printf("debug5\n");
	return 0;
}
