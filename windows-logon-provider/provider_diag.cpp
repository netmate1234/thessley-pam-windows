#include "provider_diag.h"
#include <strsafe.h>
#include <mutex>

void ProviderDiag(const wchar_t *eventName, HRESULT result, DWORD count)
{
    static std::mutex lock;
    std::lock_guard<std::mutex> guard(lock);
    HANDLE file = CreateFileW(
        L"C:\\ProgramData\\ThessleyPamWin\\credential-provider\\provider.log",
        FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return;

    SYSTEMTIME now{};
    GetSystemTime(&now);
    wchar_t line[256]{};
    if (FAILED(StringCchPrintfW(line, ARRAYSIZE(line),
            L"%04u-%02u-%02uT%02u:%02u:%02uZ event=%s hr=0x%08lX count=%lu\r\n",
            now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond,
            eventName ? eventName : L"unknown", static_cast<unsigned long>(result), count))) {
        CloseHandle(file);
        return;
    }
    char utf8[512]{};
    const int bytes = WideCharToMultiByte(CP_UTF8, 0, line, -1, utf8,
        static_cast<int>(sizeof(utf8)), nullptr, nullptr);
    if (bytes > 1) {
        DWORD written = 0;
        WriteFile(file, utf8, static_cast<DWORD>(bytes - 1), &written, nullptr);
    }
    CloseHandle(file);
}
