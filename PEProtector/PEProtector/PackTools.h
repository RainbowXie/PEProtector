#pragma once
#include "E:\Cracker\PEProtector\CommonHeader\CommonHeader.h"
#include "E:\Cracker\PEProtector\CommonHeader\MyCryptOpt.h"
class CPackTools
{
public:
    CPackTools();
    ~CPackTools();

    bool packPE(char* szOrgPath, char* szDestPath);
private:
    bool prepareOrgPE(CHAR* szPath);
    bool prepareDecryptCode();
    bool prepareSection();
    bool prepareSectionData();
    bool prepareSectionHeader();
    bool preparePEHeader();

    bool encryptData();

    DWORD getAlignValue(DWORD dwAlign, DWORD dwValue);

    bool writePEToFile(char * szNewPePath);

private:
    //
    CHAR* m_szPwd;

    //
    HANDLE m_hOrgFile = INVALID_HANDLE_VALUE;
    HANDLE m_hOrgFileMappingObject = INVALID_HANDLE_VALUE;
    LPVOID m_OrgFileMapStartAddr = NULL;

    DWORD m_iFileSize = 0;

    PE_HEADER m_PeHeader = { 0 };

    //
    DWORD m_dwDecryptCodeSize = 0;
    BYTE* m_btDecryptCode = NULL;
    DWORD m_dwEntryPointOffsetSection;  //shellcode����ڵ�����ڽ��׵�ַ��ƫ��

    //
    DWORD m_iEncryptedDataSize = 0;
    LPBYTE m_pEncryptedData = NULL;
    


    // �ڱ��
    IMAGE_SECTION_HEADER m_ImgSectionHeader[SEC_NUMBERS];       //�� PE �Ľ���Ϣ
    DWORD m_dwSectionDataSize;
    LPBYTE m_pSectionData;

    // �����ɵ� PE ��ͷ��
    LPBYTE m_pNewPEHeader;
    DWORD m_dwNewPEHeaderSize;
};

