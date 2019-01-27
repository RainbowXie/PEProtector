#pragma once
#include <windows.h>

// 节编号
enum emSecNumber
{
    SEC_SPACE,
    SEC_SHELLCODE,
    SEC_NUMBERS
};

// 解析 PE 头
typedef struct  tagHeader
{
    PIMAGE_DOS_HEADER m_pDosHeader;
    PIMAGE_NT_HEADERS m_pNtHeader;
    PIMAGE_FILE_HEADER m_pFileHeader;
    PIMAGE_OPTIONAL_HEADER m_pOptHeader;
    PIMAGE_SECTION_HEADER m_pSectionHeader;     // 第一个节的起始地址

    void analysisPE(LPBYTE m_pPEHeader)
    {
        m_pDosHeader = (PIMAGE_DOS_HEADER)m_pPEHeader;
        m_pNtHeader = (PIMAGE_NT_HEADERS)(m_pPEHeader + m_pDosHeader->e_lfanew);
        m_pFileHeader = &m_pNtHeader->FileHeader;
        m_pOptHeader = &m_pNtHeader->OptionalHeader;
        m_pSectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)m_pOptHeader + m_pFileHeader->SizeOfOptionalHeader);
    };
}PE_HEADER;