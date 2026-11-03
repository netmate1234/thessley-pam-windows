#pragma once

#include <windows.h>
#include <string>
#include <vector>

bool ThessleyPasswordVaultExists(PCWSTR sid);
HRESULT ThessleyPasswordVaultLoad(PCWSTR sid, std::vector<WCHAR> &password);
HRESULT ThessleyPasswordVaultSave(PCWSTR sid, PCWSTR password);
void ThessleySecureClear(std::vector<WCHAR> &value);
