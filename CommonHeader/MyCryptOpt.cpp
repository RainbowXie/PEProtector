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
    // 获得一个CSP句柄
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

    // 创建一个会话密钥
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

    // 加密源缓冲区，并将加密后数据写入目标缓冲区
    bool fEOF = FALSE;
    DWORD dwCount;
    DWORD dwCountLeft = dwSourceSize;  // 未拷贝的数据的大小
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

    // 加密源缓冲区，并将加密后数据写入目标缓冲区
    bool fEOF = FALSE;
    DWORD dwCount;
    DWORD dwCountLeft = dwSourceSize;  // 未拷贝的数据的大小
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
    // 打开要加密的源文件
    m_pSource = lpSourceBuf;

    // 打开加密后产生的目标文件
    m_pDestination = lpDestBuf;

    // 用输入的密码产生一个散列
    if (!CryptHashData(
        m_hHash,
        (BYTE*)lpPassword,
        strlen(lpPassword),
        0))
    {
        OutputDebugStringA("CryptHashData() failed!");
        return FALSE;
    }

    // 通过散列生成会话密钥
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

    // 因为加密算法是按ENCRYPT_BLOCK_SIZE 大小的块加密的，所以被加密的
    // 数据长度必须是ENCRYPT_BLOCK_SIZE 的整数倍。下面计算一次加密的
    // 数据长度。
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
    // 为缓冲区分配内存
    m_pbBuffer = (BYTE*)malloc(m_dwBufferLen);
    if (!m_pbBuffer)
    {
        OutputDebugStringA("分配内存错误!");
        return FALSE;
    }

    return TRUE;
}