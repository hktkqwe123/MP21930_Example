#pragma once

#include <Windows.h>
#include "WanaZip.h"

class WanaDecryptor
{
	PWanaZip m_pWanaZip;
	TCHAR m_BasePath[MAX_PATH];
	HANDLE m_hDecryptLog;

	BOOL DecryptTraverse(LPCTSTR);
	BOOL CreateDecryptLog();
public:
	WanaDecryptor();
	~WanaDecryptor();
	BOOL Init();
	BOOL InitWanaZip(DWORD);
	BOOL Decrypt(LPCTSTR);
	BOOL DecryptAll();
};

typedef WanaDecryptor* PWanaDecryptor;