#pragma once
#include "E:\Cracker\PEProtector\CommonHeader\CommonHeader.h"

class CPackTools
{
public:
    CPackTools();
    ~CPackTools();

    bool packPE(char* szOrgPath, char* szDestPath);
private:
    bool prepareOrgPE(CHAR* szPath);
    bool prepareDecompressCode();
    bool prepareSection();
    bool prepareSectionData();
    bool prepareSectionHeader();
    bool preparePEHeader();

    bool encryptData();

    DWORD getAlignValue(DWORD dwAlign, DWORD dwValue);

    bool writePEToFile(char * szNewPePath);

};

