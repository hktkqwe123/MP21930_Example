#include "EZAES.h"
#include "../Common/common.h"
#include <bcrypt.h>
#pragma comment(lib, "Bcrypt.lib")

EZAES::EZAES()
{
	m_hProv = INVALID_HANDLE_VALUE;
	m_hKey = INVALID_HANDLE_VALUE;
	m_pbIV = NULL;
	m_pbKeyObject = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	if (!NT_SUCCESS(status =
		BCryptOpenAlgorithmProvider(
			&m_hProv,
			BCRYPT_AES_ALGORITHM,
			NULL,
			0)))
	{
		DEBUG("BCryptOpenAlgorithmProvider returns 0x%x\n",
			status);
		return;
	}
	ULONG cbData;
	if (!NT_SUCCESS(status =
		BCryptGetProperty(
			m_hProv,
			BCRYPT_BLOCK_LENGTH,
			(PUCHAR)& m_cbBlock,
			sizeof(m_cbBlock),
			&cbData,
			0)))
	{
		DEBUG("BCryptGetProperty returns 0x%x\n",
			status);
		return;
	}
	m_cbIV = m_cbBlock;
	m_pbIV = (PUCHAR)HeapAlloc(
		GetProcessHeap(), 0, m_cbIV);
	if (!NT_SUCCESS(status =
		BCryptGetProperty(
			m_hProv,
			BCRYPT_OBJECT_LENGTH,
			(PUCHAR)& m_cbKeyObject,
			sizeof(m_cbKeyObject),
			&cbData,
			0)))
	{
		DEBUG("BCryptGetProperty returns 0x%x\n",
			status);
		return;
	}
	m_pbKeyObject = (PUCHAR)HeapAlloc(
		GetProcessHeap(), 0, m_cbKeyObject);
	if (NULL == m_pbKeyObject)
	{
		DEBUG("**** memory allocation failed\n");
		return;
	}
	return;
}

EZAES::~EZAES()
{
	if (m_pbIV) {
		HeapFree(GetProcessHeap(), 0, m_pbIV);
		m_pbIV = NULL;
	}
	m_cbIV = 0;
	if (m_pbKeyObject) {
		HeapFree(GetProcessHeap(), 0, m_pbKeyObject);
		m_pbKeyObject = NULL;
	}
	m_cbKeyObject = 0;
	if (m_hProv != INVALID_HANDLE_VALUE)
	{
		BCryptCloseAlgorithmProvider(m_hProv, 0);
		m_hProv = INVALID_HANDLE_VALUE;
	}
	if (m_hKey != INVALID_HANDLE_VALUE)
	{
		BCryptDestroyKey(m_hKey);
		m_hKey = INVALID_HANDLE_VALUE;
	}
	return;
}

BOOL EZAES::GenKey(PUCHAR pbKey, ULONG cbKey)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG cbKeyObject = 0;
	if (!NT_SUCCESS(status =
		BCryptGenerateSymmetricKey(
			m_hProv,
			&m_hKey,
			m_pbKeyObject,
			m_cbKeyObject,
			pbKey,
			cbKey,
			0)))
	{
		DEBUG("BCryptGenerateSymmetricKey returns 0x%x\n",
			status);
		return FALSE;
	}
	Init();
	return TRUE;
}

BOOL EZAES::Init()
{
	if (m_pbIV && m_cbIV) {
		ZeroMemory(m_pbIV, m_cbIV);
	}
	return TRUE;
}

BOOL EZAES::Encrypt(
	PUCHAR pbPlain,
	ULONG cbPlain,
	PUCHAR pbCipher,
	ULONG cbCipher,
	PULONG pcbResult)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG cbData;
	if (!NT_SUCCESS(status =
		BCryptEncrypt(
			m_hKey,
			pbPlain,
			cbPlain,
			NULL,
			m_pbIV,
			m_cbIV,
			NULL,
			0,
			&cbData,
			0)))
	{
		DEBUG("AES BCryptEncrypt#1 0x%x\n",
			status);
		return NULL;
	}
	if (pcbResult) {
		*pcbResult = cbData;
	}
	if (cbCipher < cbData) {
		return FALSE;
	}
	if (!NT_SUCCESS(status =
		BCryptEncrypt(
			m_hKey,
			pbPlain,
			cbPlain,
			NULL,
			m_pbIV,
			m_cbIV,
			pbCipher,
			cbData,
			&cbData,
			0)))
	{
		DEBUG("AES BCryptEncrypt#2 0x%x\n",
			status);
		return NULL;
	}
	if (pcbResult) {
		*pcbResult = cbData;
	}
	return TRUE;
}
BOOL EZAES::Decrypt(
	PUCHAR pbCipher,
	ULONG cbCipher,
	PUCHAR pbPlain,
	ULONG cbPlain,
	PULONG pcbResult)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG cbData;
	if (!NT_SUCCESS(status =
		BCryptDecrypt(
			m_hKey,
			pbCipher,
			cbCipher,
			NULL,
			m_pbIV,
			m_cbIV,
			NULL,
			0,
			&cbData,
			0)))
	{
		DEBUG("EZAES::BCryptDecrypt#1 returns 0x%x\n",
			status);
		return NULL;
	}
	if (pcbResult) {
		*pcbResult = cbData;
	}
	if (cbPlain < cbData) {
		return FALSE;
	}
	if (!NT_SUCCESS(status =
		BCryptDecrypt(
			m_hKey,
			pbCipher,
			cbCipher,
			NULL,
			m_pbIV,
			m_cbIV,
			pbPlain,
			cbData,
			&cbData,
			0)))
	{
		DEBUG("EZAES::BCryptDecrypt#2 returns 0x%x\n",
			status);
		return NULL;
	}
	return TRUE;
}
