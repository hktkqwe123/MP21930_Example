#pragma once

#include <Windows.h>
#include <bcrypt.h>

class EZAES
{
	BCRYPT_HANDLE m_hProv;
	BCRYPT_KEY_HANDLE m_hKey;
	ULONG m_cbBlock;
	PUCHAR m_pbIV;
	ULONG m_cbIV;
	PUCHAR m_pbKeyObject;
	ULONG m_cbKeyObject;
public:
	EZAES();
	~EZAES();
	BOOL GenKey(PUCHAR, ULONG);
	BOOL Init();
	BOOL Encrypt(PUCHAR, ULONG, PUCHAR, ULONG, PULONG);
	BOOL Decrypt(PUCHAR, ULONG, PUCHAR, ULONG, PULONG);

};

typedef EZAES* PEZAES;

