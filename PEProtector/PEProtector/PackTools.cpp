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
    //打开并映射原 PE
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

    // 获取 PE 头部数据
    m_PeHeader.analysisPE((LPBYTE)m_OrgFileMapStartAddr);

    return true;
}

bool CPackTools::prepareDecryptCode()
{
    HANDLE hFile = CreateFileA("H:\\CR31\\壳\\20190125\\ShellCode\\Release\\ShellCode.exe", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
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

    //拷贝第一个节的节数据
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
    // 申请节区数据所需要的内存
    // 大小为已压缩的数据大小 + sizeof(数据偏移) + sizeof(已压缩数据大小) + 解压缩 shellcode 代码大小
    m_dwSectionDataSize = m_iEncryptedDataSize
        + m_dwDecryptCodeSize
        + sizeof(tagCompressedDataInfo);
    m_dwSectionDataSize = getAlignValue(m_PeHeader.m_pOptHeader->FileAlignment, m_dwSectionDataSize); //对齐

                                                                                                      //节数据
    m_pSectionData = new BYTE[m_dwSectionDataSize];

    // 拷贝数据
    tagCompressedDataInfo ci;
    ci.m_dwCompressedDataOffset = sizeof(tagCompressedDataInfo) + m_dwDecryptCodeSize;
    ci.m_dwCompressedDataSize = m_iEncryptedDataSize;
    ci.m_dwDecomDataSize = m_iFileSize;
    memcpy(m_pSectionData, &ci, sizeof(tagCompressedDataInfo));
    memcpy(
        m_pSectionData + sizeof(tagCompressedDataInfo),
        m_btDecryptCode,
        m_dwDecryptCodeSize); //拷贝解压缩数据的大小
    memcpy(
        m_pSectionData + m_dwDecryptCodeSize + sizeof(tagCompressedDataInfo),
        m_pEncryptedData, m_iEncryptedDataSize); //拷贝压缩数据


    return true;
}

bool CPackTools::prepareSectionHeader()
{
    // 构建空节
    // 空节在内存中展开的大小应为原来被压缩的 PE 的大小
    CHAR szName[] = "Empty";
    strcpy_s((char*)m_ImgSectionHeader[SEC_SPACE].Name, sizeof(szName), szName);
    m_ImgSectionHeader[SEC_SPACE].Misc.VirtualSize = m_PeHeader.m_pOptHeader->SizeOfImage;
    m_ImgSectionHeader[SEC_SPACE].VirtualAddress = m_PeHeader.m_pSectionHeader->VirtualAddress;     //新 PE 使用的是原 PE 头改的新 PE 头，而 PE 头完了之后就是 节表，所以节表起始地址和原来一样
    m_ImgSectionHeader[SEC_SPACE].PointerToRawData = 0;
    m_ImgSectionHeader[SEC_SPACE].SizeOfRawData = 0;
    m_ImgSectionHeader[SEC_SPACE].Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA
        | IMAGE_SCN_MEM_EXECUTE
        | IMAGE_SCN_MEM_READ
        | IMAGE_SCN_MEM_WRITE;

    // 构建数据节
    strcpy((char*)m_ImgSectionHeader[SEC_SHELLCODE].Name, "Packed");
    m_ImgSectionHeader[SEC_SHELLCODE].Misc.VirtualSize = getAlignValue(m_PeHeader.m_pOptHeader->SectionAlignment, m_dwSectionDataSize);     // 数据节在内存中展开的大小
    m_ImgSectionHeader[SEC_SHELLCODE].VirtualAddress = m_ImgSectionHeader[SEC_SPACE].VirtualAddress + m_ImgSectionHeader[SEC_SPACE].Misc.VirtualSize;   //空节的起始地址 + 空节的大小 = 数据节的起始地址
    m_ImgSectionHeader[SEC_SHELLCODE].PointerToRawData = m_PeHeader.m_pOptHeader->SizeOfHeaders;    //因为第一个节是空节，所以文件地址接着 PE 头之后
    m_ImgSectionHeader[SEC_SHELLCODE].SizeOfRawData = m_dwSectionDataSize;
    m_ImgSectionHeader[SEC_SHELLCODE].Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA
        | IMAGE_SCN_MEM_EXECUTE
        | IMAGE_SCN_MEM_READ
        | IMAGE_SCN_MEM_WRITE;

    return true;
}

bool CPackTools::preparePEHeader()
{
    //申请内存，存放新的PE头
    m_dwNewPEHeaderSize = m_PeHeader.m_pOptHeader->SizeOfHeaders;
    m_pNewPEHeader = new BYTE[m_dwNewPEHeaderSize];

    //拷贝原来的PE头
    memcpy(m_pNewPEHeader, m_OrgFileMapStartAddr, m_dwNewPEHeaderSize);

    //解析PE头
    PE_HEADER tagPeHeader = { 0 };
    tagPeHeader.analysisPE(m_pNewPEHeader);

    //修改头部
    tagPeHeader.m_pFileHeader->NumberOfSections = SEC_NUMBERS;
    tagPeHeader.m_pOptHeader->AddressOfEntryPoint = m_ImgSectionHeader[SEC_SHELLCODE].VirtualAddress;   // 程序从解压代码处开始执行
    tagPeHeader.m_pOptHeader->SizeOfImage = m_ImgSectionHeader[SEC_SHELLCODE].VirtualAddress + m_ImgSectionHeader[SEC_SHELLCODE].Misc.VirtualSize;  //大小为 PE 头加节大小

    memcpy(tagPeHeader.m_pSectionHeader, m_ImgSectionHeader, sizeof(m_ImgSectionHeader)); //拷贝节表

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
    WriteFile(hFile, m_pNewPEHeader, m_dwNewPEHeaderSize, &dwBytesToWrite, NULL); //写入新头部
    WriteFile(hFile, m_pSectionData, m_dwSectionDataSize, &dwBytesToWrite, NULL); //写入新头部

    CloseHandle(hFile);
    return true;
}
