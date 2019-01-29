#include "StdAfx.h"
#include "MyCryptOpt.h"

CMyCryptOpt::CMyCryptOpt(void)
{

}

CMyCryptOpt::~CMyCryptOpt(void)
{

}

BOOL CMyCryptOpt::InitCrypt()
{
    // ���һ��CSP���
    if (!CryptAcquireContext(&m_hCryptProv, NULL, NULL, PROV_RSA_FULL, 0))
    {
        if (!CryptAcquireContext(
            &m_hCryptProv,
            NULL,
            NULL,
            PROV_RSA_FULL,
            CRYPT_NEWKEYSET))
        {
            OutputDebugStringA("CryptAcquireContext() error!");
            return FALSE;
        }
    }

    // ����һ���Ự��Կ
    if (!CryptCreateHash(
        m_hCryptProv,
        CALG_MD5,
        0,
        0,
        &m_hHash))
    {
        OutputDebugStringA("CryptCreateHash() error!");

        return FALSE;
    }
    return TRUE;
}

void CMyCryptOpt::DestroyCrypt()
{
    m_pSource = NULL;
    m_pDestination = NULL;

    // free memory
    if (m_pbBuffer)
        free(m_pbBuffer);

    // destroy session key
    if (m_hKey)
        CryptDestroyKey(m_hKey);

    // destroy hash object
    CryptDestroyHash(m_hHash);
    m_hHash = NULL;

    // Release provider handle
    if (m_hCryptProv)
        CryptReleaseContext(m_hCryptProv, 0);
}

BOOL CMyCryptOpt::MyEncryptBuf(LPBYTE lpSourceBuf, DWORD dwSourceSize, LPBYTE *lpDestBuf, LPDWORD pdwDestSize, LPSTR lpPassword)
{
    m_pdwDestSize = pdwDestSize;

    // process for encrypt
    if (!CryptProcess(lpSourceBuf, lpDestBuf, lpPassword))
        return FALSE;

    // ����Դ���������������ܺ�����д��Ŀ�껺����
    bool fEOF = FALSE;
    DWORD dwCount;
    DWORD dwCountLeft = dwSourceSize;  // δ���������ݵĴ�С
    std::stringbuf sb;
    std::ostream os(&sb);
    std::istream is(&sb);

    while (dwCountLeft > 0)
    {
        dwCount = 0;

        // read source
        if (dwCountLeft > m_dwBlockLen)
        {
            memcpy(m_pbBuffer, m_pSource, m_dwBlockLen);
            dwCountLeft -= m_dwBlockLen;
            dwCount = m_dwBlockLen;
        }
        else
        {
            memcpy(m_pbBuffer, m_pSource, dwCountLeft);
            dwCount = dwCountLeft;
            dwCountLeft -= dwCountLeft;
            fEOF = TRUE;
        }

        // encrypt data
        if (!CryptEncrypt(
            m_hKey,
            0,
            fEOF,
            0,
            m_pbBuffer,
            &dwCount,
            m_dwBufferLen))
        {
            OutputDebugStringA("CryptEncrypt() failed!");
            return FALSE;
        }
        // write data 

        os.write((char*)m_pbBuffer, dwCount);
        *m_pdwDestSize += dwCount;
    }
    *lpDestBuf = (LPBYTE)malloc(*m_pdwDestSize);
    is.read((char*)*lpDestBuf, *m_pdwDestSize);

    return TRUE;
}

BOOL CMyCryptOpt::MyDecryptBuf(LPBYTE lpSourceBuf, DWORD dwSourceSize, LPBYTE *lpDestBuf, LPDWORD pdwDestSize, LPSTR lpPassword)
{
    m_pdwDestSize = pdwDestSize;

    // process for encrypt
    if (!CryptProcess(lpSourceBuf, lpDestBuf, lpPassword))
        return FALSE;

    // ����Դ���������������ܺ�����д��Ŀ�껺����
    bool fEOF = FALSE;
    DWORD dwCount;
    DWORD dwCountLeft = dwSourceSize;  // δ���������ݵĴ�С
    std::stringbuf sb;
    std::ostream os(&sb);
    std::istream is(&sb);

    while (dwCountLeft > 0)
    {
        dwCount = 0;

        // read source
        if (dwCountLeft > m_dwBlockLen)
        {
            memcpy(m_pbBuffer, m_pSource, m_dwBlockLen);
            dwCountLeft -= m_dwBlockLen;
            dwCount = m_dwBlockLen;
        }
        else
        {
            memcpy(m_pbBuffer, m_pSource, dwCountLeft);
            dwCount = dwCountLeft;
            dwCountLeft -= dwCountLeft;
            fEOF = TRUE;
        }

        // encrypt data
        if (!CryptDecrypt(
            m_hKey,
            0,
            fEOF,
            0,
            m_pbBuffer,
            &dwCount))
        {
            OutputDebugStringA("CryptEncrypt() failed!");
            return FALSE;
        }
        // write data 

        os.write((char*)m_pbBuffer, dwCount);
        *m_pdwDestSize += dwCount;
    }
    *lpDestBuf = (LPBYTE)malloc(*m_pdwDestSize);
    is.read((char*)*lpDestBuf, *m_pdwDestSize);

    return TRUE;
}

BOOL CMyCryptOpt::CryptProcess(LPBYTE lpSourceBuf, LPBYTE* lpDestBuf, LPSTR lpPassword)
{
    // ��Ҫ���ܵ�Դ�ļ�
    m_pSource = lpSourceBuf;

    // �򿪼��ܺ������Ŀ���ļ�
    m_pDestination = lpDestBuf;

    // ��������������һ��ɢ��
    if (!CryptHashData(
        m_hHash,
        (BYTE*)lpPassword,
        strlen(lpPassword),
        0))
    {
        OutputDebugStringA("CryptHashData() failed!");
        return FALSE;
    }

    // ͨ��ɢ�����ɻỰ��Կ
    if (!CryptDeriveKey(
        m_hCryptProv,
        ENCRYPT_ALGORITHM,
        m_hHash,
        KEYLENGTH,
        &m_hKey))
    {
        OutputDebugStringA("CryptDeriveKey() failed!");

        return FALSE;
    }

    // ��Ϊ�����㷨�ǰ�ENCRYPT_BLOCK_SIZE ��С�Ŀ���ܵģ����Ա����ܵ�
    // ���ݳ��ȱ�����ENCRYPT_BLOCK_SIZE �����������������һ�μ��ܵ�
    // ���ݳ��ȡ�
    m_dwBlockLen = 1000 - 1000 % ENCRYPT_BLOCK_SIZE;

    // Determine the block size. If a block cipher is used,
    // it must have room for an extra block.

    if (ENCRYPT_BLOCK_SIZE > 1)
    {
        m_dwBufferLen = m_dwBlockLen + ENCRYPT_BLOCK_SIZE;
    }
    else
    {
        m_dwBufferLen = m_dwBlockLen;
    }
    // Ϊ�����������ڴ�
    m_pbBuffer = (BYTE*)malloc(m_dwBufferLen);
    if (!m_pbBuffer)
    {
        OutputDebugStringA("�����ڴ����!");
        return FALSE;
    }

    return TRUE;
}