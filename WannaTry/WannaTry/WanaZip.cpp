#include "WanaZip.h"
#include "../Common/common.h"
#pragma comment(lib, "Bcrypt.lib")

BOOL GenRandom(
	PUCHAR pbBuffer,
	ULONG cbBuffer)
{
	NTSTATUS status = BCryptGenRandom(
		NULL,
		pbBuffer,
		cbBuffer,
		BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	if (!NT_SUCCESS(status))
	{
		DEBUG("BCryptGenRandom returns 0x%x\n",
			status);
		return FALSE;
	}
	return TRUE;
}

WanaZip::WanaZip()
{
	m_pEncRSA = NULL;
	m_pDecRSA = NULL;
	m_InBuffer = (PUCHAR)HeapAlloc(
		GetProcessHeap(),
		0,
		WZIP_IOBUFFERSIZE);
	m_OutBuffer = (PUCHAR)HeapAlloc(
		GetProcessHeap(),
		0,
		WZIP_IOBUFFERSIZE);
	return;
}

WanaZip::~WanaZip()
{
	if (m_pEncRSA) {
		delete m_pEncRSA;
		m_pEncRSA = NULL;
	}
	if (m_pDecRSA) {
		delete m_pDecRSA;
		m_pDecRSA = NULL;
	}
	if (m_InBuffer) {
		HeapFree(GetProcessHeap(), 0, m_InBuffer);
		m_InBuffer = NULL;
	}
	if (m_OutBuffer) {
		HeapFree(GetProcessHeap(), 0, m_OutBuffer);
		m_OutBuffer = NULL;
	}
	return;
}

BOOL WanaZip::ImportPublicKey(
	PUCHAR pbPublicBlob,
	ULONG cbPublicBlob)
{
	if (!m_pEncRSA) {
		m_pEncRSA = new EZRSA();
		if (!m_pEncRSA) {
			return FALSE;
		}
	}
	BOOL bResult = m_pEncRSA->Import(
		BCRYPT_RSAPUBLIC_BLOB,
		pbPublicBlob,
		cbPublicBlob);
	return bResult;
}

BOOL WanaZip::ImportPrivateKey(
	PUCHAR pbPrivateBlob,
	ULONG cbPrivateBlob)
{
	if (!m_pDecRSA) {
		m_pDecRSA = new EZRSA();
		if (!m_pDecRSA) {
			return FALSE;
		}
	}
	BOOL bResult = m_pDecRSA->Import(
		BCRYPT_RSAPRIVATE_BLOB,
		pbPrivateBlob,
		cbPrivateBlob);
	return bResult;
}
BOOL WanaZip::ImportPublicKey(
	LPCTSTR PublicBlobFile)
{
	if (!m_pEncRSA) {
		m_pEncRSA = new EZRSA();
		if (!m_pEncRSA) {
			return FALSE;
		}
	}
	BOOL bResult = m_pEncRSA->Import(
		BCRYPT_RSAPUBLIC_BLOB,
		PublicBlobFile);
	return bResult;
}

BOOL WanaZip::ImportPrivateKey(
	LPCTSTR PrivateBlobFile)
{
	if (!m_pDecRSA) {
		m_pDecRSA = new EZRSA();
		if (!m_pDecRSA) {
			return FALSE;
		}
	}
	BOOL bResult = m_pDecRSA->Import(
		BCRYPT_RSAPRIVATE_BLOB,
		PrivateBlobFile);
	DEBUG("ImportPrivateKey: return %d\n",
		bResult);
	return bResult;
}



BOOL WanaZip::Encrypt(
	LPCTSTR pFileName,
	ULONG EncryptOP)
{
	UCHAR abMagic[8];
	ULONG cbCipherKey;
	UCHAR abCipherKey[0x200];
	ULONG nCryptType = DO_NOTHING;
	LARGE_INTEGER ddwFileSize;
	PEZAES pAES = NULL;
	UCHAR abKey[16];
	HANDLE hFile = INVALID_HANDLE_VALUE;
	HANDLE hWrite = INVALID_HANDLE_VALUE;
	ULONG cbRead = NULL, cbWrite = NULL;
	FILETIME CreationTime;
	FILETIME LastAccessTime;
	FILETIME LastWriteTime;
	BOOL bResult = TRUE;
	PUCHAR pbInBlock = m_InBuffer;
	ULONG cbInBlock = 0;
	PUCHAR pbOutBlock = m_OutBuffer;
	ULONG cbOutBlock = 0;
	TCHAR pTempFile[MAX_PATH];
	TCHAR pTarget[MAX_PATH];
	if (!m_pEncRSA) {
		DEBUG("m_EncRSA is NULL, please call ImportPublicKey()\n");
		return FALSE;
	}
	if (EncryptOP != DO_ENCRYPT) {
		DEBUG("WriteSRC %s\n", pFileName);
		_stprintf_s(pTarget, MAX_PATH,
			_T("%s%s"), pFileName,
			WZIP_SUFFIX_WRITESRC);
	}
	else {
		DEBUG("Encrypt %s\n", pFileName);
		_tcscpy_s(pTarget, MAX_PATH, pFileName);
		LPTSTR pSuffix = (LPTSTR)
			_tcsrchr(pTarget, _T('.'));
		if (!pSuffix) {
			_tcscat_s(pTarget, MAX_PATH,
				WZIP_SUFFIX_CIPHER);
		}
		else {
			if (_tcsicmp(pSuffix,
				WZIP_SUFFIX_WRITESRC)) {
				_tcscat_s(pTarget,
					MAX_PATH,
					WZIP_SUFFIX_CIPHER);
			}
			else {
				_tcscpy_s(pSuffix,
					MAX_PATH - _tcslen(pFileName),
					WZIP_SUFFIX_CIPHER);
			}
		}
	}
	if (!(hFile = CreateFile(
		pFileName,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL)))
	{
		DEBUG("Open %s for read error\n",
			pFileName);
		return FALSE;
	}
	ddwFileSize.QuadPart = 0;
	GetFileTime(
		hFile,
		&CreationTime,
		&LastAccessTime,
		&LastWriteTime);
	if (ReadFile(
		hFile,
		abMagic, 
		sizeof(abMagic),
		&cbRead,
		0) &&
		!memcmp(abMagic, WZIP_MAGIC, sizeof(abMagic)) &&
		ReadFile(
			hFile,
			&cbCipherKey,
			sizeof(cbCipherKey),
			&cbRead,
			0) &&
		cbCipherKey <= sizeof(abCipherKey) &&
		cbCipherKey == 0x100 &&
		ReadFile(
			hFile,
			abCipherKey,
			0x100,
			&cbRead,
			0) &&
		ReadFile(
			hFile,
			&nCryptType,
			sizeof(nCryptType),
			&cbRead,
			0) &&
		ReadFile(
			hFile,
			&ddwFileSize.QuadPart,
			sizeof(ddwFileSize),
			&cbRead,
			0) &&
		nCryptType >= EncryptOP) {
		CloseHandle(hFile);
		hFile = INVALID_HANDLE_VALUE;
		return TRUE;
	}
	// not encrypted
	if (nCryptType == DO_NOTHING) {
		GetFileSizeEx(hFile, &ddwFileSize);
		SetFilePointer(hFile, 0, 0, FILE_BEGIN);
	}
	//
	if (EncryptOP == DO_ENCRYPT) {
		_stprintf_s(pTempFile, MAX_PATH,
			_T("%s%s"), pFileName, WZIP_SUFFIX_TEMP);
		if ((hWrite = CreateFile(
			pTempFile,
			GENERIC_WRITE,
			FILE_SHARE_READ,
			NULL, CREATE_ALWAYS,
			FILE_ATTRIBUTE_NORMAL,
			NULL)) == INVALID_HANDLE_VALUE) {
			DEBUG("Open temp file %s error\n",
				pTempFile);
			CloseHandle(hFile);
			hFile = INVALID_HANDLE_VALUE;
			return FALSE;
		}
	}
	else {
		cbCipherKey = 0x100;
		nCryptType = DO_WRITESRC;
		PUCHAR pbBlock = m_InBuffer;
		SetFilePointer(hFile, 0, 0, FILE_BEGIN);
		if (!ReadFile(
			hFile,
			pbBlock,
			WZIP_SRCBUFFERSIZE,
			&cbRead,
			0) || cbRead != WZIP_SRCBUFFERSIZE) {
			DEBUG("WriteSRC read error %s\n",
				pFileName);
			goto Error_Exit;
		}
		SetFilePointer(hFile, 0, 0, FILE_END);
		if (!WriteFile(
			hFile,
			pbBlock,
			WZIP_SRCBUFFERSIZE,
			&cbWrite,
			0) || cbWrite != WZIP_SRCBUFFERSIZE) {
			DEBUG("WriteSRC write error %s\n",
				pTempFile);
			goto Error_Exit;
		}
		ZeroMemory(pbBlock, WZIP_SRCBUFFERSIZE);
		SetFilePointer(hFile, 0, 0, FILE_BEGIN);
		if (!WriteFile(
			hFile,
			pbBlock,
			WZIP_SRCBUFFERSIZE,
			&cbWrite,
			0) || cbWrite != WZIP_SRCBUFFERSIZE) {
			DEBUG("WriteSRC fill 0x00 error %s\n",
				pTempFile);
			goto Error_Exit;
		}
		SetFilePointer(hFile, 0, 0, FILE_BEGIN);
		hWrite = hFile;
	}
	//
	GenRandom(abKey, sizeof(abKey));
	m_pEncRSA->Encrypt(
		abKey,
		sizeof(abKey),
		abCipherKey,
		sizeof(abCipherKey),
		&cbCipherKey);
	pAES = new EZAES();
	pAES->GenKey(abKey, sizeof(abKey));
	if (!WriteFile(hWrite,
		WZIP_MAGIC, 8, &cbWrite, 0) ||
		!WriteFile(hWrite,
			&cbCipherKey, sizeof(cbCipherKey), &cbWrite, 0) ||
		!WriteFile(hWrite,
			abCipherKey, cbCipherKey, &cbWrite, 0) ||
		!WriteFile(hWrite,
			&EncryptOP, sizeof(EncryptOP), &cbWrite, 0) ||
		!WriteFile(hWrite,
			&ddwFileSize.QuadPart,
			sizeof(ddwFileSize.QuadPart),
			&cbWrite,
			0)) {
		DEBUG("Write header error %s\n",
			pTempFile);
		goto Error_Exit;
	}
	if (EncryptOP == DO_ENCRYPT) {
		ULONG cbData;
		LARGE_INTEGER cbSize;
		cbSize.QuadPart = ddwFileSize.QuadPart;
		if (nCryptType == DO_WRITESRC) {
			SetFilePointer(
				hFile,
				-WZIP_SRCBUFFERSIZE,
				0,
				FILE_END);
			if (!ReadFile(hFile,
				pbInBlock,
				WZIP_SRCBUFFERSIZE,
				&cbRead,
				0) || cbRead != WZIP_SRCBUFFERSIZE) {
				DEBUG("WriteSRC read error %s\n",
					pFileName);
				goto Error_Exit;
			}
			pAES->Encrypt(
				pbInBlock,
				WZIP_SRCBUFFERSIZE,
				pbOutBlock,
				WZIP_IOBUFFERSIZE,
				&cbData);
			if (!WriteFile(
				hWrite,
				pbOutBlock,
				WZIP_SRCBUFFERSIZE,
				&cbWrite,
				0) || cbWrite != WZIP_SRCBUFFERSIZE) {
				DEBUG("WriteSRC write error %s\n",
					pTempFile);
				goto Error_Exit;
			}
			SetFilePointer(hFile,
				WZIP_SRCBUFFERSIZE, 0, FILE_BEGIN);
			cbSize.QuadPart -= WZIP_SRCBUFFERSIZE;
		}
		while (cbSize.QuadPart > 0) {
			cbInBlock = cbSize.QuadPart < WZIP_IOBUFFERSIZE ?
				cbSize.LowPart : WZIP_IOBUFFERSIZE;
			if (!ReadFile(
				hFile,
				pbInBlock,
				cbInBlock,
				&cbRead,
				0) || cbRead != cbInBlock) {
				DEBUG("Read Block error %s\n",
					pFileName);
				goto Error_Exit;
			}
			cbOutBlock = ((cbInBlock + 15) >> 4) << 4;
			if (cbOutBlock > cbInBlock) {
				ZeroMemory(pbInBlock + cbInBlock,
					cbOutBlock - cbInBlock);
			}
			pAES->Encrypt(
				pbInBlock,
				cbOutBlock,
				pbOutBlock,
				WZIP_IOBUFFERSIZE,
				&cbData);
			if (!WriteFile(
				hWrite,
				pbOutBlock,
				cbOutBlock,
				&cbWrite,
				0) || cbWrite != cbOutBlock) {
				DEBUG("Write Block error %s\n",
					pTempFile);
				goto Error_Exit;
			}
			cbSize.QuadPart -= cbInBlock;
		}
	}
	SetFileTime(hWrite,
		&CreationTime,
		&LastAccessTime,
		&LastWriteTime);

	if (EncryptOP == DO_ENCRYPT) {
		CloseHandle(hWrite);
		CloseHandle(hFile);
		hWrite = INVALID_HANDLE_VALUE;
		hFile = INVALID_HANDLE_VALUE;
		bResult = MoveFile(pTempFile, pTarget);
		if (bResult) {
			SetFileAttributes(pTarget,
				FILE_ATTRIBUTE_NORMAL);
			DeleteFile(pFileName);
		}
		else {
			DeleteFile(pTempFile);
		}
	}
	else {
		CloseHandle(hFile);
		hWrite = INVALID_HANDLE_VALUE;
		hFile = INVALID_HANDLE_VALUE;
		bResult = MoveFile(pFileName, pTarget);
		if (bResult) {
			SetFileAttributes(pTarget,
				FILE_ATTRIBUTE_NORMAL);
		}
	}
	if (pAES) {
		delete pAES;
		pAES = NULL;
	}
	return bResult;
Error_Exit:
	if (EncryptOP == DO_ENCRYPT) {
		CloseHandle(hWrite);
		hWrite = INVALID_HANDLE_VALUE;
	}
	CloseHandle(hFile);
	hFile = INVALID_HANDLE_VALUE;
	if (pAES) {
		delete pAES;
		pAES = NULL;
	}
	return FALSE;
}



BOOL WanaZip::Decrypt(LPCTSTR pFileName)
{
	TCHAR pTempFile[MAX_PATH];
	TCHAR pTarget[MAX_PATH];
	UCHAR abMagic[8];
	ULONG cbCipherKey;
	UCHAR abCipherKey[0x200];
	ULONG nCryptType = DO_NONE;
	LARGE_INTEGER ddwFileSize;
	UCHAR abKey[0x200];
	ULONG cbKey;
	PEZAES pAES = NULL;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	HANDLE hWrite = INVALID_HANDLE_VALUE;
	ULONG cbRead, cbWrite;
	FILETIME CreationTime;
	FILETIME LastAccessTime;
	FILETIME LastWriteTime;
	PUCHAR pbInBlock = m_InBuffer;
	ULONG cbInBlock = 0;
	PUCHAR pbOutBlock = m_OutBuffer;
	ULONG cbOutBlock = 0;
	BOOL bResult = TRUE;
	if (!m_pDecRSA) {
		DEBUG("m_DecRSA is NULL, please call ImportPrivateKey()\n");
		return FALSE;
	}
	DEBUG("Decrypt %s\n", pFileName);
	if ((hFile = CreateFile(
		pFileName,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL)) == INVALID_HANDLE_VALUE) {
		return FALSE;
	}
	GetFileTime(
		hFile,
		&CreationTime,
		&LastAccessTime,
		&LastWriteTime);
	if (ReadFile(hFile, abMagic,
		sizeof(abMagic), &cbRead, 0) &&
		!memcmp(abMagic, WZIP_MAGIC,
			sizeof(abMagic)) &&
		ReadFile(hFile, &cbCipherKey,
			sizeof(cbCipherKey), &cbRead, 0) &&
		cbCipherKey <= sizeof(abCipherKey) &&
		cbCipherKey == 0x100 &&
		ReadFile(hFile, abCipherKey,
			0x100, &cbRead, 0) &&
		ReadFile(hFile, &nCryptType,
			sizeof(nCryptType), &cbRead, 0) &&
		nCryptType >= DO_WRITESRC &&
		ReadFile(hFile, &ddwFileSize.QuadPart,
			sizeof(ddwFileSize.QuadPart), &cbRead, 0)) {
		_tcscpy_s(pTarget, MAX_PATH, pFileName);
		LPTSTR pSuffix = _tcsrchr(pTarget, _T('.'));
		if (pSuffix) {
			if (nCryptType == DO_WRITESRC &&
				!_tcsicmp(pSuffix, WZIP_SUFFIX_TEMP)) {
				*pSuffix = _T('\0');
			}
			else if (nCryptType == DO_ENCRYPT &&
				!_tcsicmp(pSuffix, WZIP_SUFFIX_CIPHER)) {
				*pSuffix = _T('\0');
			}
			else {
				_stprintf_s(pTarget, MAX_PATH, _T("%s%s"),
					pFileName, _T(".decoded"));
			}
		}
		if (nCryptType == DO_WRITESRC) {
			SetFilePointer(
				hFile,
				-WZIP_SRCBUFFERSIZE,
				0,
				FILE_END);
			if (!ReadFile(
				hFile,
				pbInBlock,
				WZIP_SRCBUFFERSIZE,
				&cbRead,
				0) || cbRead != WZIP_SRCBUFFERSIZE) {
				goto Error_Exit;
			}
			SetFilePointer(hFile, 0, 0, FILE_BEGIN);
			if (!WriteFile(
				hFile,
				pbInBlock,
				WZIP_SRCBUFFERSIZE,
				&cbWrite,
				0) || cbWrite != WZIP_SRCBUFFERSIZE) {
				goto Error_Exit;
			}
			SetFilePointer(hFile,
				-WZIP_SRCBUFFERSIZE,
				0,
				FILE_END);
			SetEndOfFile(hFile);
			SetFileTime(hFile,
				&CreationTime,
				&LastAccessTime,
				&LastWriteTime);
		}
		else {
			_stprintf_s(pTempFile, MAX_PATH,
				_T("%s%s"), pFileName, WZIP_SUFFIX_TEMP);
			if ((hWrite = CreateFile(
				pTempFile,
				GENERIC_WRITE,
				FILE_SHARE_READ,
				NULL,
				CREATE_ALWAYS,
				FILE_ATTRIBUTE_NORMAL, NULL))
				== INVALID_HANDLE_VALUE) {
				DEBUG("CreateFile %s fails\n",
					pTarget);
				goto Error_Exit;
			}
			LARGE_INTEGER cbSize;

			pAES = new EZAES();
			m_pDecRSA->Decrypt(
				abCipherKey,
				cbCipherKey,
				abKey,
				sizeof(abKey),
				&cbKey);
			if (cbKey != 16) {
				goto Error_Exit;
			}
			pAES->GenKey(abKey, cbKey);
			ULONG cbData;
			for (cbSize.QuadPart = ddwFileSize.QuadPart;
				cbSize.QuadPart > 0;
				cbSize.QuadPart -= cbOutBlock) {
				cbOutBlock =
					cbSize.QuadPart < WZIP_IOBUFFERSIZE ?
					cbSize.LowPart : WZIP_IOBUFFERSIZE;
				cbInBlock = ((cbOutBlock + 15) >> 4) << 4;
				if (!ReadFile(
					hFile,
					pbInBlock,
					cbInBlock,
					&cbRead, 0) || cbRead != cbInBlock) {
					goto Error_Exit;
				}
				pAES->Decrypt(
					pbInBlock,
					cbInBlock,
					pbOutBlock,
					WZIP_IOBUFFERSIZE,
					&cbData);
				if (!WriteFile(
					hWrite,
					pbOutBlock,
					cbOutBlock,
					&cbWrite,
					0) || cbWrite != cbOutBlock) {
					DEBUG("Write block error %s\n",
						pTarget);
					goto Error_Exit;
				}
			}
			SetFileTime(hWrite,
				&CreationTime,
				&LastAccessTime,
				&LastWriteTime);
		}
	}
	else {
		CloseHandle(hFile);
		hFile = INVALID_HANDLE_VALUE;
		return TRUE;
	}

	if (nCryptType == DO_ENCRYPT) {
		CloseHandle(hWrite);
		CloseHandle(hFile);
		hWrite = INVALID_HANDLE_VALUE;
		hFile = INVALID_HANDLE_VALUE;
		bResult = MoveFileEx(
			pTempFile,
			pTarget,
			MOVEFILE_REPLACE_EXISTING);
		if (bResult) {
			DeleteFile(pFileName);
		}
	}
	else {
		CloseHandle(hFile);
		hFile = INVALID_HANDLE_VALUE;
		bResult = MoveFileEx(
			pFileName,
			pTarget,
			MOVEFILE_REPLACE_EXISTING);
	}
	if (pAES) {
		delete pAES;
		pAES = NULL;
	}
	return bResult;
Error_Exit:
	if (nCryptType == DO_ENCRYPT) {
		CloseHandle(hWrite);
		hWrite = INVALID_HANDLE_VALUE;
	}
	CloseHandle(hFile);
	hFile = INVALID_HANDLE_VALUE;
	if (pAES) {
		delete pAES;
		pAES = NULL;
	}
	return FALSE;
}
