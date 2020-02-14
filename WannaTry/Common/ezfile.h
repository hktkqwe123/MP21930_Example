#pragma once

#include <Windows.h>
#include "common.h"
#include "hexdump.h"

BOOL ReadBuffer(
	LPCTSTR,
	LARGE_INTEGER,
	DWORD,
	PUCHAR,
	ULONG,
	PULONG);

BOOL WriteBuffer(
	LPCTSTR,
	LARGE_INTEGER,
	DWORD,
	PUCHAR,
	ULONG,
	PULONG);

BOOL ReadFile_DEBUG(
	HANDLE,
	LPVOID,
	DWORD,
	LPDWORD,
	LPOVERLAPPED);

BOOL WriteFile_DEBUG(
	HANDLE,
	LPCVOID,
	DWORD,
	LPDWORD,
	LPOVERLAPPED);

BOOL UpdateFileAttributes(
	LPCTSTR,
	DWORD,
	BOOL
);

BOOL DeleteFileZero(
	LPCTSTR
);

BOOL FakeDeleteFile(
	LPCTSTR
);