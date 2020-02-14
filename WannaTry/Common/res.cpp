#include <Windows.h>
#include "res.h"
#include "common.h"

// https://docs.microsoft.com/en-us/windows/win32/menurc/using-resources

BOOL ReadResource(
	LPCTSTR pFileName,
	ULONG nID,
	LPCTSTR lpType,
	PUCHAR pbData,
	ULONG cbData,
	PULONG pcbRead)
{
	HMODULE hModule;
	if (pFileName) {
		DEBUG("LoadLibrary\n");
		hModule = LoadLibrary(pFileName);
	}
	else {
		DEBUG("GetModuleHandle\n");
		hModule = GetModuleHandle(NULL);
	}
	if (!hModule) {
		DEBUG("hModule error\n");
		return FALSE;
	}
	HRSRC hResource = FindResource(
		hModule,
		MAKEINTRESOURCE(nID),
		lpType);
	if (!hResource) {
		DEBUG("FindResource error\n");
		return FALSE;
	}
	HGLOBAL hMemory = LoadResource(
		hModule,
		hResource);
	if (!hMemory) {
		DEBUG("LoadResource error\n");
		return FALSE;
	}
	DWORD dwSize = SizeofResource(
		hModule,
		hResource);
	if (!dwSize) {
		DEBUG("SizeofResource error\n");
		return FALSE;
	}
	LPVOID lpAddress = LockResource(hMemory);
	if (!lpAddress) {
		DEBUG("LockResource error\n");
		return FALSE;
	}
	ULONG size = dwSize <= cbData ? dwSize : cbData;
	memcpy(pbData, lpAddress, size);
	if (pcbRead) {
		*pcbRead = size;
	}
	if (pFileName) {
		DEBUG("FreeLibrary\n");
		if (!FreeLibrary(hModule)) {
			DEBUG("FreeLibrary error\n");
			return FALSE;
		}
	}
	return TRUE;
}

BOOL WriteResource(
	LPCTSTR pFileName,
	ULONG nID,
	LPCTSTR lpType,
	PUCHAR pbData,
	ULONG cbData)
{
	HMODULE hModule;
	BOOL bResult;
	if (pFileName) {
		DEBUG("LoadLibrary\n");
		hModule = LoadLibrary(pFileName);
	}
	else {
		DEBUG("GetModuleHandle\n");
		hModule = GetModuleHandle(NULL);
	}
	if (!hModule) {
		DEBUG("Get handle error\n");
		return FALSE;
	}
	HANDLE hResource = BeginUpdateResource(
		pFileName,
		FALSE);
	if (hResource == NULL)
	{
		DEBUG("BeginUpdateResource error\n");
		return FALSE;
	}
	bResult = UpdateResource(hResource,
		lpType,
		MAKEINTRESOURCE(nID),
		MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
		pbData,
		cbData);
	if (!bResult) {
		DEBUG("UpdateResource error\n");
		return FALSE;
	}
	if (!EndUpdateResource(hResource, FALSE))
	{
		DEBUG("EndUpdateResource error: %d\n",
			GetLastError());
		return FALSE;
	}
	if (pFileName) {
		DEBUG("FreeLibrary\n");
		if (!FreeLibrary(hModule)) {
			DEBUG("FreeLibrary error\n");
			return FALSE;
		}
	}
	return TRUE;
}