#include "common.h"
#include "ezfile.h"
#include "hexdump.h"

#ifndef FAKEDELETESUFFIX
#define FAKEDELETESUFFIX _T(".wanabak")
#endif

BOOL ReadBuffer(
	LPCTSTR lpFileName,
	LARGE_INTEGER liDistanceToMove,
	DWORD dwMoveMethod,
	PUCHAR pbBuffer,
	ULONG cbBuffer,
	PULONG pcbResult)
{
	HANDLE hFile;
	LARGE_INTEGER liNewFilePointer;
	BOOL bResult = FALSE;

	if ((hFile = CreateFile(
		lpFileName,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	)) == INVALID_HANDLE_VALUE) {
		DEBUG("open %s fails: %d\n",
			lpFileName, GetLastError());
		return FALSE;
	}

	if (!SetFilePointerEx(
		hFile,
		liDistanceToMove,
		&liNewFilePointer,
		dwMoveMethod)) {
		DEBUG("set pointer %s fails: %d\n",
			lpFileName, GetLastError());
		goto Error_Exit;
	}

	if (!(bResult = ReadFile(
		hFile,
		pbBuffer,
		cbBuffer,
		pcbResult,
		0))) {
		DEBUG("Read %s error: %d\n",
			lpFileName, GetLastError());
	}
	bResult = TRUE;
Error_Exit:
	CloseHandle(hFile);
	return bResult;
}

BOOL WriteBuffer(
	LPCTSTR lpFileName,
	LARGE_INTEGER liDistanceToMove,
	DWORD dwMoveMethod,
	PUCHAR pbBuffer,
	ULONG cbBuffer,
	PULONG pcbResult)
{
	HANDLE hFile;
	LARGE_INTEGER liNewFilePointer;
	BOOL bResult = FALSE;

	if ((hFile = CreateFile(
		lpFileName,
		GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	)) == INVALID_HANDLE_VALUE) {
		DEBUG("Open file %s error\n",
			lpFileName);
		return FALSE;
	}

	if (!SetFilePointerEx(
		hFile,
		liDistanceToMove,
		&liNewFilePointer,
		dwMoveMethod)) {
		DEBUG("set pointer %s fails: %d\n",
			lpFileName, GetLastError());
		goto Error_Exit;
	}

	if (!(bResult = WriteFile(
		hFile,
		pbBuffer,
		cbBuffer,
		pcbResult,
		0
	))) {
		DEBUG("Write %s error\n",
			lpFileName);
	}
	bResult = TRUE;
Error_Exit:
	CloseHandle(hFile);
	return bResult;
}

BOOL ReadFile_DEBUG(
	HANDLE       hFile,
	LPVOID       lpBuffer,
	DWORD        nNumberOfBytesToRead,
	LPDWORD      lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped
)
{
	BOOL retval = ReadFile(
		hFile,
		lpBuffer,
		nNumberOfBytesToRead,
		lpNumberOfBytesRead,
		lpOverlapped
	);
	DEBUG("Read %d\n", nNumberOfBytesToRead);
	hexdump((PUCHAR)lpBuffer, nNumberOfBytesToRead);
	return retval;
}

BOOL WriteFile_DEBUG(
	HANDLE       hFile,
	LPCVOID      lpBuffer,
	DWORD        nNumberOfBytesToWrite,
	LPDWORD      lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped
)
{
	DEBUG("Write %d\n", nNumberOfBytesToWrite);
	hexdump((PUCHAR)lpBuffer, nNumberOfBytesToWrite);
	return WriteFile(
		hFile,
		lpBuffer,
		nNumberOfBytesToWrite,
		lpNumberOfBytesWritten,
		lpOverlapped
	);
}



BOOL DeleteFileZero(LPCTSTR lpFileName)
{
	HANDLE hFile;
	BOOL bResult = TRUE;
	PUCHAR abBuffer[4096];
	LARGE_INTEGER FileSize;
	if ((hFile = CreateFile(
		lpFileName,
		GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	)) == INVALID_HANDLE_VALUE) {
		DEBUG("Open file %s error\n",
			lpFileName);
		goto Error_Exit;
	}
	GetFileSizeEx(hFile, &FileSize);
	ZeroMemory(abBuffer, sizeof(abBuffer));
	for (LONGLONG p = 0;
		p < FileSize.QuadPart;
		p += sizeof(abBuffer)) {
		DWORD cbBuffer =
			(DWORD) (p < sizeof(abBuffer) ? 
			p : sizeof(abBuffer));
		if (!(bResult = WriteFile(
			hFile,
			abBuffer,
			cbBuffer,
			NULL,
			0
		))) {
			DEBUG("Write %s error\n",
				lpFileName);
			break;
		}
	}
	CloseHandle(hFile);
Error_Exit:
	DeleteFile(lpFileName);
	return TRUE;
}

BOOL UpdateFileAttributes(
	LPCTSTR lpFileName,
	DWORD dwFileAttributes,
	BOOL bFlag
)
{
	BOOL bResult = TRUE;
	DWORD dwAttrs = GetFileAttributes(lpFileName);
	if (dwAttrs == INVALID_FILE_ATTRIBUTES) {
		return FALSE;
	}
	if (bFlag) {
		if (!(dwAttrs & dwFileAttributes))
		{
			bResult = SetFileAttributes(lpFileName,
				dwAttrs | dwFileAttributes);
		}
	}
	else {
		if (dwAttrs & dwFileAttributes)
		{
			DWORD dwNewAttrs = dwAttrs &
				~dwFileAttributes;
			bResult = SetFileAttributes(lpFileName,
				dwNewAttrs);
		}
	}
	return bResult;
}

BOOL FakeDeleteFile(LPCTSTR lpFileName)
{
	TCHAR newFileName[MAX_PATH];
	LPCTSTR suffix;
	BOOL bResult = FALSE;
	if ((suffix = _tcsrchr(lpFileName, _T('.')))) {
		if (!_tcsnicmp(suffix + 1, FAKEDELETESUFFIX, 8)) {
			return TRUE;
		}
	}
	_stprintf_s(newFileName, _T("%s%s"),
		lpFileName, FAKEDELETESUFFIX);
	bResult = MoveFileEx(lpFileName, newFileName,
		MOVEFILE_REPLACE_EXISTING);
	if (bResult) {
		bResult = UpdateFileAttributes(newFileName,
			FILE_ATTRIBUTE_HIDDEN, TRUE);
	}
	return bResult;
}

BOOL FakeUndeleteFile(LPCTSTR lpFileName)
{
	TCHAR newFileName[MAX_PATH];
	TCHAR* suffix;
	BOOL bResult = FALSE;
	_tcscpy_s(newFileName, lpFileName);
	if (!(suffix = _tcsrchr(newFileName, _T('.')))) {
		return TRUE;
	}
	if (!_tcsnicmp(suffix, FAKEDELETESUFFIX, 8)) {
		*suffix = 0;
		bResult = MoveFile(lpFileName, newFileName);
	}
	if (bResult) {
		bResult = UpdateFileAttributes(lpFileName,
			FILE_ATTRIBUTE_HIDDEN, FALSE);
	}
	return bResult;
}