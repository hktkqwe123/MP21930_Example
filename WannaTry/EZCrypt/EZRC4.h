#pragma once

#include <Windows.h>
#include <bcrypt.h>
#include "../Common/common.h"
class EZRC4 {
protected:
	BCRYPT_HANDLE m_hProv;
	BCRYPT_KEY_HANDLE m_hKey;

public:
	EZRC4();
	~EZRC4();
	BOOL GenKey(PUCHAR, ULONG);
	BOOL Encrypt(PUCHAR, ULONG, PUCHAR, ULONG, PULONG);
	BOOL Decrypt(PUCHAR, ULONG, PUCHAR, ULONG, PULONG);
};

typedef EZRC4* PEZRC4;

