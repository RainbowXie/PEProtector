#include "stdafx.h"
#include "PackTools.h"


CPackTools::CPackTools()
{
    m_szPwd = "password";
}


CPackTools::~CPackTools()
{
}

bool CPackTools::packPE(char * szOrgPath, char * szDestPath)
{
    prepareOrgPE(szOrgPath);
    prepareDecryptCode();
    encryptData();
    prepareSection();
    preparePEHeader();

    writePEToFile(szDestPath);

    return false;
}

bool CPackTools::prepareOrgPE(CHAR * szPath)
{
    //�򿪲�ӳ��ԭ PE
    m_hOrgFile = CreateFileA(
        szPath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        0);
    if (INVALID_HANDLE_VALUE == m_hOrgFile)
    {
        //cleanResourse();
        return false;
    }

    DWORD dwFileSizeHigh = 0;
    DWORD dwFlieSizeLow = GetFileSize(m_hOrgFile, &dwFileSizeHigh);
    m_iFileSize = dwFileSizeHigh;
    m_iFileSize << 32;
    m_iFileSize += dwFlieSizeLow;

    m_hOrgFileMappingObject = CreateFileMappingA(
        m_hOrgFile,
        NULL,
        PAGE_READONLY,
        dwFileSizeHigh,
        dwFlieSizeLow,
        NULL);
    if (INVALID_HANDLE_VALUE == m_hOrgFileMappingObject)
    {
        //cleanResourse();
        return false;
    }

    m_OrgFileMapStartAddr = MapViewOfFile(
        m_hOrgFileMappingObject,
        FILE_MAP_READ,
        0, 0, 0);
    if (NULL == m_OrgFileMapStartAddr)
    {
        //cleanResourse();
        return false;
    }

    // ��ȡ PE ͷ������
    m_PeHeader.analysisPE((LPBYTE)m_OrgFileMapStartAddr);

    return true;
}

bool CPackTools::prepareDecryptCode()
{
    HANDLE hFile = CreateFileA("H:\\CR31\\��\\20190125\\ShellCode\\Release\\ShellCode.exe", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (INVALID_HANDLE_VALUE == hFile) {
        return false;
    }
    DWORD dwFileSize = GetFileSize(hFile, NULL);


    HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (NULL == hMapping)
    {
        return false;
    }

    LPBYTE pShellCodePEBuff = (LPBYTE)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (NULL == pShellCodePEBuff)
    {
        return false;
    }

    PE_HEADER shellcodePE;
    shellcodePE.analysisPE(pShellCodePEBuff);

    //������һ���ڵĽ�����
    m_dwDecryptCodeSize = shellcodePE.m_pSectionHeader[0].SizeOfRawData;
    m_btDecryptCode = new BYTE[m_dwDecryptCodeSize];
    memcpy(m_btDecryptCode, pShellCodePEBuff + shellcodePE.m_pSectionHeader[0].PointerToRawData, m_dwDecryptCodeSize);

    m_dwEntryPointOffsetSection = shellcodePE.m_pOptHeader->AddressOfEntryPoint - shellcodePE.m_pSectionHeader[0].VirtualAddress;

    return true;
}

bool CPackTools::prepareSection()
{
    prepareSectionData();
    prepareSectionHeader();
    return false;
}

bool CPackTools::prepareSectionData()
{
    // ���������������Ҫ���ڴ�
    // ��СΪ��ѹ�������ݴ�С + sizeof(����ƫ��) + sizeof(��ѹ�����ݴ�С) + ��ѹ�� shellcode �����С
    m_dwSectionDataSize = m_iEncryptedDataSize
        + m_dwDecryptCodeSize
        + sizeof(tagCompressedDataInfo);
    m_dwSectionDataSize = getAlignValue(m_PeHeader.m_pOptHeader->FileAlignment, m_dwSectionDataSize); //����

                                                                                                      //������
    m_pSectionData = new BYTE[m_dwSectionDataSize];

    // ��������
    tagCompressedDataInfo ci;
    ci.m_dwCompressedDataOffset = sizeof(tagCompressedDataInfo) + m_dwDecryptCodeSize;
    ci.m_dwCompressedDataSize = m_iEncryptedDataSize;
    ci.m_dwDecomDataSize = m_iFileSize;
    memcpy(m_pSectionData, &ci, sizeof(tagCompressedDataInfo));
    memcpy(
        m_pSectionData + sizeof(tagCompressedDataInfo),
        m_btDecryptCode,
        m_dwDecryptCodeSize); //������ѹ�����ݵĴ�С
    memcpy(
        m_pSectionData + m_dwDecryptCodeSize + sizeof(tagCompressedDataInfo),
        m_pEncryptedData, m_iEncryptedDataSize); //����ѹ������


    return true;
}

bool CPackTools::prepareSectionHeader()
{
    // �����ս�
    // �ս����ڴ���չ���Ĵ�СӦΪԭ����ѹ���� PE �Ĵ�С
    CHAR szName[] = "Empty";
    strcpy_s((char*)m_ImgSectionHeader[SEC_SPACE].Name, sizeof(szName), szName);
    m_ImgSectionHeader[SEC_SPACE].Misc.VirtualSize = m_PeHeader.m_pOptHeader->SizeOfImage;
    m_ImgSectionHeader[SEC_SPACE].VirtualAddress = m_PeHeader.m_pSectionHeader->VirtualAddress;     //�� PE ʹ�õ���ԭ PE ͷ�ĵ��� PE ͷ���� PE ͷ����֮����� �ڱ����Խڱ���ʼ��ַ��ԭ��һ��
    m_ImgSectionHeader[SEC_SPACE].PointerToRawData = 0;
    m_ImgSectionHeader[SEC_SPACE].SizeOfRawData = 0;
    m_ImgSectionHeader[SEC_SPACE].Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA
        | IMAGE_SCN_MEM_EXECUTE
        | IMAGE_SCN_MEM_READ
        | IMAGE_SCN_MEM_WRITE;

    // �������ݽ�
    strcpy((char*)m_ImgSectionHeader[SEC_SHELLCODE].Name, "Packed");
    m_ImgSectionHeader[SEC_SHELLCODE].Misc.VirtualSize = getAlignValue(m_PeHeader.m_pOptHeader->SectionAlignment, m_dwSectionDataSize);     // ���ݽ����ڴ���չ���Ĵ�С
    m_ImgSectionHeader[SEC_SHELLCODE].VirtualAddress = m_ImgSectionHeader[SEC_SPACE].VirtualAddress + m_ImgSectionHeader[SEC_SPACE].Misc.VirtualSize;   //�սڵ���ʼ��ַ + �սڵĴ�С = ���ݽڵ���ʼ��ַ
    m_ImgSectionHeader[SEC_SHELLCODE].PointerToRawData = m_PeHeader.m_pOptHeader->SizeOfHeaders;    //��Ϊ��һ�����ǿսڣ������ļ���ַ���� PE ͷ֮��
    m_ImgSectionHeader[SEC_SHELLCODE].SizeOfRawData = m_dwSectionDataSize;
    m_ImgSectionHeader[SEC_SHELLCODE].Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA
        | IMAGE_SCN_MEM_EXECUTE
        | IMAGE_SCN_MEM_READ
        | IMAGE_SCN_MEM_WRITE;

    return true;
}

bool CPackTools::preparePEHeader()
{
    //�����ڴ棬����µ�PEͷ
    m_dwNewPEHeaderSize = m_PeHeader.m_pOptHeader->SizeOfHeaders;
    m_pNewPEHeader = new BYTE[m_dwNewPEHeaderSize];

    //����ԭ����PEͷ
    memcpy(m_pNewPEHeader, m_OrgFileMapStartAddr, m_dwNewPEHeaderSize);

    //����PEͷ
    PE_HEADER tagPeHeader = { 0 };
    tagPeHeader.analysisPE(m_pNewPEHeader);

    //�޸�ͷ��
    tagPeHeader.m_pFileHeader->NumberOfSections = SEC_NUMBERS;
    tagPeHeader.m_pOptHeader->AddressOfEntryPoint = m_ImgSectionHeader[SEC_SHELLCODE].VirtualAddress;   // ����ӽ�ѹ���봦��ʼִ��
    tagPeHeader.m_pOptHeader->SizeOfImage = m_ImgSectionHeader[SEC_SHELLCODE].VirtualAddress + m_ImgSectionHeader[SEC_SHELLCODE].Misc.VirtualSize;  //��СΪ PE ͷ�ӽڴ�С

    memcpy(tagPeHeader.m_pSectionHeader, m_ImgSectionHeader, sizeof(m_ImgSectionHeader)); //�����ڱ�

    return true;
}

bool CPackTools::encryptData()
{
    CMyCryptOpt cryptOpt;

    cryptOpt.InitCrypt();
    cryptOpt.MyEncryptBuf((LPBYTE)m_OrgFileMapStartAddr, m_iFileSize, &m_pEncryptedData, &m_iEncryptedDataSize, m_szPwd);
    cryptOpt.DestroyCrypt();

    return true;
}

DWORD CPackTools::getAlignValue(DWORD dwAlign, DWORD dwValue)
{
    if (dwValue % dwAlign == 0)
    {
        return dwValue;
    }

    return (dwValue / dwAlign + 1) * dwAlign;
}

bool CPackTools::writePEToFile(char * szNewPePath)
{
    HANDLE hFile = CreateFileA(szNewPePath,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        0);

    if (INVALID_HANDLE_VALUE == hFile) 
    {
        return false;
    }

    DWORD dwBytesToWrite = 0;
    WriteFile(hFile, m_pNewPEHeader, m_dwNewPEHeaderSize, &dwBytesToWrite, NULL); //д����ͷ��
    WriteFile(hFile, m_pSectionData, m_dwSectionDataSize, &dwBytesToWrite, NULL); //д����ͷ��

    CloseHandle(hFile);
    return true;
}
