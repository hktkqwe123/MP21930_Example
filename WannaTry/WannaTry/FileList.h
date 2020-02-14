#pragma once
#include <Windows.h>
#include "../Common/common.h"

#define FILETYPE_UNKNOWN	0
#define FILETYPE_EXE_DLL	1
#define FILETYPE_HIGH_PRIORITY	2
#define FILETYPE_LOW_PRIORITY	3
#define FILETYPE_ZIP_TEMP	4
#define FILETYPE_WRITESRC	5
#define FILETYPE_ENCRYPTED	6

#ifndef BASE_DIRNAME
#define BASE_DIRNAME _T("WANNATRY")
#endif
#ifndef ENCRYPT_ROOT_PATH
// #define ENCRYPT_ROOT_PATH _T("C:\\")
#define ENCRYPT_ROOT_PATH _T("C:\\TESTDATA\\")
#endif

struct FileInfo {
	TCHAR m_szFullPath[360];
	TCHAR m_szName[260];
	LARGE_INTEGER m_cbFileSize;
	DWORD m_dwFileType;
};

typedef FileInfo* PFileInfo;

struct FileNode {
	FileNode* m_pPrev;
	FileNode* m_pNext;
	FileInfo m_Info;
};

typedef FileNode* PFileNode;

class FileList
{
public:
	PFileNode m_pHead = NULL;
	ULONG m_nFiles = 0;
	FileList();
	~FileList();
	BOOL Insert(PFileNode);
};

typedef FileList* PFileList;

BOOL isIgnorePath(LPCTSTR, LPCTSTR);
DWORD ClassifyFileType(LPCTSTR);


