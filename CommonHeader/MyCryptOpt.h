#pragma once

#include <windows.h>
#include <wincrypt.h>
#include <string>
#include <istream>
#include <iostream>
#include <streambuf>
#include <sstream>
#include <fstream>
#include <string>



#define MY_ENCODING_TYPE (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
#define  KEYLENGTH 0x00800000
#define ENCRYPT_ALGORITHM CALG_RC4
#define ENCRYPT_BLOCK_SIZE 8

class CMyCryptOpt
{

public:

    CMyCryptOpt(void);

    ~CMyCryptOpt(void);

    BOOL InitCrypt();

    void DestroyCrypt();

    BOOL MyEncryptBuf(LPBYTE lpSourceBuf, DWORD dwSourceSize, LPBYTE *lpDestBuf, LPDWORD dwDestSize, LPSTR lpPassword);

    BOOL MyDecryptBuf(LPBYTE lpSourceBuf, DWORD dwSourceSize, LPBYTE *lpDestBuf, LPDWORD pdwDestSize, LPSTR lpPassword);

protected:

    BOOL CryptProcess(LPBYTE lpSourceBuf, LPBYTE *lpDestBuf, LPSTR lpPassword);

private:

    LPBYTE m_pSource;
    LPBYTE *m_pDestination;
    HCRYPTPROV m_hCryptProv;
    HCRYPTKEY m_hKey;
    HCRYPTHASH m_hHash;
    PBYTE m_pbBuffer;
    DWORD m_dwBlockLen;
    DWORD m_dwBufferLen;
    LPDWORD m_pdwDestSize;
};
