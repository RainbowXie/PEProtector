// EncryptionShell.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <stdlib.h>
#include <iostream>
#include <windows.h>
#include "PackTools.h"
int main()
{
    char szName[MAX_PATH] = { 0 };
    std::cin.get(szName, MAX_PATH);

    char szDrive[_MAX_DRIVE] = { 0 };
    char szDir[_MAX_DIR] = { 0 };
    char szFName[_MAX_FNAME] = { 0 };
    char szExt[_MAX_EXT] = { 0 };
    _splitpath(szName, szDrive, szDir, szFName, szExt);

    char szDstName[MAX_PATH] = { 0 };
    sprintf_s(szDstName, "%s%s%s%s%s", szDrive, szDir, szFName, "_Pack", szExt);

    CPackTools *packer = new CPackTools;
    packer->packPE(szName, szDstName);

    return 0;
}

