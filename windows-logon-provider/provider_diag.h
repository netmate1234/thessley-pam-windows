#pragma once

#include <windows.h>

// Logs only provider lifecycle events and numeric results. Never pass identity,
// password, QR, or approval data to this function.
void ProviderDiag(const wchar_t *eventName, HRESULT result = S_OK, DWORD count = 0);
