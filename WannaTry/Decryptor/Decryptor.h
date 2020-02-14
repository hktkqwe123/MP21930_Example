#pragma once

#include "resource.h"
#include <Windows.h>
#include <Richedit.h>
#include <CommCtrl.h>
#include "../Common/common.h"

#ifndef BUTTON_CLASS
#define BUTTON_CLASS _T("BUTTON")
#endif
#ifndef STATIC_CLASS
#define STATIC_CLASS _T("STATIC")
#endif
#ifndef EDIT_CLASS
#define EDIT_CLASS _T("EDIT")
#endif
#ifndef COMBOBOX_CLASS
#define COMBOBOX_CLASS _T("COMBOBOX")
#endif
#ifndef PROGRESS_CLASS
#define PROGRESS_CLASS _T("msctls_progress32")
#endif

#define BACKGROUND RGB(0x90, 0x20, 0x26)

#define IDT_TIMER1 9001
#define IDT_TIMER2 9002
#define IDT_TIMER3 9003

// Information type in szMessage of DECRYPTCOMM

#define IDI_DECRYPTED_DIR 2101
#define IDI_DECRYPTED_FILE 2102
#define IDI_DECRYPTED_DONE 2103
#define IDI_INDEX 2111


// Command Send to Decryption Thread from Decryption Dialog (click start/stop)

#define IDC_DECRYPT_START 2201
#define IDC_DECRYPT_STOP 2202

#ifndef DECRYPT_SERVER_PORT
#define DECRYPT_SERVER_PORT "9050"
#endif

#ifndef MUTEX_NAME
#define MUTEX_NAME (_T("Global\\MsWinZonesCacheCounterMutex"))
#endif

#ifndef RESOURCE_PASSWORD
#define RESOURCE_PASSWORD "WNcry@2olP"
#endif

#ifndef PRICE_COUNTDOWN
#define PRICE_COUNTDOWN (3 * 86400)
#endif

#ifndef FINAL_COUNTDOWN
#define FINAL_COUNTDOWN (7 * 86400)
#endif

#undef DEBUG
#define DEBUG(...) (0)

