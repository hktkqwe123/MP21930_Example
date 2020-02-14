#include "EZRC4.h"

EZRC4::EZRC4()
{
	m_hProv = NULL;
	m_hKey = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	if (!NT_SUCCESS(status =
		BCryptOpenAlgorithmProvider(
			&m_hProv,
			BCRYPT_RC4_ALGORITHM,
			NULL,
			0)))
	{
		DEBUG("BCryptOpenAlgorithmProvider returns 0x%x\n",
			status);
		return;
	}
	return;
}

EZRC4::~EZRC4()
{
	if (m_hProv)
	{
		BCryptCloseAlgorithmProvider(m_hProv, 0);
		m_hProv = NULL;
	}
	if (m_hKey)
	{
		BCryptDestroyKey(m_hKey);
		m_hKey = NULL;
	}
	return;
}

BOOL EZRC4::GenKey(PUCHAR pbKey, ULONG cbKey)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	if (!NT_SUCCESS(status =
		BCryptGenerateSymmetricKey(
			m_hProv,
			&m_hKey,
			NULL,
			0,
			pbKey,
			cbKey,
			0)))
	{
		DEBUG("BCryptGenerateSymmetricKey returns 0x%x\n",
			status);
		return FALSE;
	}
	return TRUE;
}

BOOL EZRC4::Encrypt(
	PUCHAR pbPlain,
	ULONG cbPlain,
	PUCHAR pbCipher,
	ULONG cbCipher,
	PULONG pcbResult)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	if (!NT_SUCCESS(status =
		BCryptEncrypt(
			m_hKey,
			pbPlain,
			cbPlain,
			NULL,
			NULL,
			0,
			pbCipher,
			cbCipher,
			pcbResult,
			0))) {
		DEBUG("BCryptEncrypt returns 0x%x\n",
			status);
	}
	return TRUE;
}

BOOL EZRC4::Decrypt(
	PUCHAR pbCipher,
	ULONG cbCipher,
	PUCHAR pbPlain,
	ULONG cbPlain,
	PULONG pcbResult)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	if (!NT_SUCCESS(status =
		BCryptDecrypt(
			m_hKey,
			pbCipher,
			cbCipher,
			NULL,
			NULL,
			0,
			pbPlain,
			cbPlain,
			pcbResult,
			0)))
	{
		DEBUG("BCryptDecrypt returns 0x%x\n",
			status);
		return FALSE;
	}
	return TRUE;
}

