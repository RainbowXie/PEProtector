#include "stdafx.h"
#include "PackTools.h"


CPackTools::CPackTools()
{
}


CPackTools::~CPackTools()
{
}

bool CPackTools::packPE(char * szOrgPath, char * szDestPath)
{
    return false;
}

bool CPackTools::prepareOrgPE(CHAR * szPath)
{
    return false;
}

bool CPackTools::prepareDecompressCode()
{
    return false;
}

bool CPackTools::prepareSection()
{
    return false;
}

bool CPackTools::prepareSectionData()
{
    return false;
}

bool CPackTools::prepareSectionHeader()
{
    return false;
}

bool CPackTools::preparePEHeader()
{
    return false;
}

bool CPackTools::encryptData()
{
    return false;
}

DWORD CPackTools::getAlignValue(DWORD dwAlign, DWORD dwValue)
{
    return 0;
}

bool CPackTools::writePEToFile(char * szNewPePath)
{
    return false;
}
