#include "password_vault.h"

#include <dpapi.h>
#include <sddl.h>
#include <strsafe.h>
#include <vector>

namespace
{
constexpr DWORD kMaxPasswordChars = 1024;
constexpr DWORD kMaxBlobBytes = 8192;
constexpr WCHAR kVaultDirectory[] = L"C:\\ProgramData\\ThessleyPamWin\\credential-provider\\vault";

bool GetVaultPath(PCWSTR sidText, std::wstring &path)
{
    if (!sidText || !*sidText) return false;

    PSID sid = nullptr;
    if (!ConvertStringSidToSidW(sidText, &sid)) return false;
    if (!IsValidSid(sid))
    {
        LocalFree(sid);
        return false;
    }

    LPWSTR canonicalSid = nullptr;
    const BOOL converted = ConvertSidToStringSidW(sid, &canonicalSid);
    LocalFree(sid);
    if (!converted) return false;

    WCHAR filename[MAX_PATH]{};
    const HRESULT hr = StringCchPrintfW(filename, ARRAYSIZE(filename), L"%s\\%s.bin",
                                        kVaultDirectory, canonicalSid);
    LocalFree(canonicalSid);
    if (FAILED(hr)) return false;
    path.assign(filename);
    return true;
}

bool MakeEntropy(PCWSTR sidText, std::vector<BYTE> &entropy)
{
    std::wstring path;
    if (!GetVaultPath(sidText, path)) return false;
    // Bind the DPAPI blob to both this feature and the canonical account SID.
    // This value is context, not a secret; DPAPI provides confidentiality and integrity.
    std::wstring context = L"ThessleyPamWin QR vault v1|";
    const size_t separator = path.find_last_of(L'\\');
    if (separator == std::wstring::npos) return false;
    context.append(path.substr(separator + 1, path.size() - separator - 5)); // SID, without .bin
    entropy.resize((context.size() + 1) * sizeof(WCHAR));
    memcpy(entropy.data(), context.c_str(), entropy.size());
    SecureZeroMemory(context.data(), context.size() * sizeof(WCHAR));
    return true;
}

bool EnsureVaultDirectory()
{
    if (CreateDirectoryW(kVaultDirectory, nullptr)) return true;
    if (GetLastError() != ERROR_ALREADY_EXISTS) return false;
    const DWORD attributes = GetFileAttributesW(kVaultDirectory);
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) &&
           !(attributes & FILE_ATTRIBUTE_REPARSE_POINT);
}

bool WriteAll(HANDLE file, const BYTE *data, DWORD size)
{
    DWORD written = 0;
    while (written < size)
    {
        DWORD current = 0;
        if (!WriteFile(file, data + written, size - written, &current, nullptr) || current == 0)
            return false;
        written += current;
    }
    return FlushFileBuffers(file) != FALSE;
}
}

void ThessleySecureClear(std::vector<WCHAR> &value)
{
    if (!value.empty()) SecureZeroMemory(value.data(), value.size() * sizeof(WCHAR));
    value.clear();
    value.shrink_to_fit();
}

bool ThessleyPasswordVaultExists(PCWSTR sid)
{
    std::wstring path;
    if (!GetVaultPath(sid, path)) return false;
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY) &&
           !(attributes & FILE_ATTRIBUTE_REPARSE_POINT);
}

HRESULT ThessleyPasswordVaultLoad(PCWSTR sid, std::vector<WCHAR> &password)
{
    ThessleySecureClear(password);
    std::wstring path;
    std::vector<BYTE> entropy;
    if (!GetVaultPath(sid, path) || !MakeEntropy(sid, entropy)) return E_INVALIDARG;

    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_HIDDEN | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (file == INVALID_HANDLE_VALUE) return HRESULT_FROM_WIN32(GetLastError());

    BY_HANDLE_FILE_INFORMATION fileInfo{};
    LARGE_INTEGER fileSize{};
    bool validFile = GetFileInformationByHandle(file, &fileInfo) &&
                     !(fileInfo.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) &&
                     GetFileSizeEx(file, &fileSize) && fileSize.QuadPart > 0 && fileSize.QuadPart <= kMaxBlobBytes;
    std::vector<BYTE> encrypted;
    if (validFile)
    {
        encrypted.resize(static_cast<size_t>(fileSize.QuadPart));
        DWORD read = 0;
        validFile = ReadFile(file, encrypted.data(), static_cast<DWORD>(encrypted.size()), &read, nullptr) &&
                    read == encrypted.size();
    }
    CloseHandle(file);
    if (!validFile)
    {
        if (!encrypted.empty()) SecureZeroMemory(encrypted.data(), encrypted.size());
        return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    }

    DATA_BLOB input{static_cast<DWORD>(encrypted.size()), encrypted.data()};
    DATA_BLOB optionalEntropy{static_cast<DWORD>(entropy.size()), entropy.data()};
    DATA_BLOB output{};
    const BOOL ok = CryptUnprotectData(&input, nullptr, &optionalEntropy, nullptr, nullptr,
                                       CRYPTPROTECT_UI_FORBIDDEN, &output);
    SecureZeroMemory(encrypted.data(), encrypted.size());
    SecureZeroMemory(entropy.data(), entropy.size());
    if (!ok) return HRESULT_FROM_WIN32(GetLastError());

    HRESULT result = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    if (output.cbData >= sizeof(WCHAR) && output.cbData <= (kMaxPasswordChars + 1) * sizeof(WCHAR) &&
        output.cbData % sizeof(WCHAR) == 0)
    {
        const auto *plain = reinterpret_cast<const WCHAR *>(output.pbData);
        const size_t charCount = output.cbData / sizeof(WCHAR);
        if (plain[charCount - 1] == L'\0')
        {
            size_t length = 0;
            while (length + 1 < charCount && plain[length] != L'\0') ++length;
            if (length > 0 && length + 1 == charCount)
            {
                password.assign(plain, plain + charCount);
                result = S_OK;
            }
        }
    }
    SecureZeroMemory(output.pbData, output.cbData);
    LocalFree(output.pbData);
    return result;
}

HRESULT ThessleyPasswordVaultSave(PCWSTR sid, PCWSTR password)
{
    if (!sid || !password || !*password) return E_INVALIDARG;
    const size_t passwordLength = wcsnlen(password, kMaxPasswordChars + 1);
    if (passwordLength == 0 || passwordLength > kMaxPasswordChars) return HRESULT_FROM_WIN32(ERROR_INVALID_PASSWORD);

    std::wstring path;
    std::vector<BYTE> entropy;
    if (!GetVaultPath(sid, path) || !MakeEntropy(sid, entropy)) return E_INVALIDARG;
    if (!EnsureVaultDirectory()) return HRESULT_FROM_WIN32(GetLastError());

    DATA_BLOB input{static_cast<DWORD>((passwordLength + 1) * sizeof(WCHAR)),
                    reinterpret_cast<BYTE *>(const_cast<PWSTR>(password))};
    DATA_BLOB optionalEntropy{static_cast<DWORD>(entropy.size()), entropy.data()};
    DATA_BLOB encrypted{};
    const BOOL protectedOk = CryptProtectData(&input, L"Thessley QR sign-in", &optionalEntropy,
                                               nullptr, nullptr,
                                               CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
                                               &encrypted);
    SecureZeroMemory(entropy.data(), entropy.size());
    if (!protectedOk) return HRESULT_FROM_WIN32(GetLastError());
    if (encrypted.cbData == 0 || encrypted.cbData > kMaxBlobBytes)
    {
        SecureZeroMemory(encrypted.pbData, encrypted.cbData);
        LocalFree(encrypted.pbData);
        return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    }

    WCHAR temporaryPath[MAX_PATH]{};
    const HRESULT pathHr = StringCchPrintfW(temporaryPath, ARRAYSIZE(temporaryPath),
                                             L"%s.tmp.%lu.%llu", path.c_str(), GetCurrentProcessId(),
                                             static_cast<unsigned long long>(GetTickCount64()));
    if (FAILED(pathHr))
    {
        SecureZeroMemory(encrypted.pbData, encrypted.cbData);
        LocalFree(encrypted.pbData);
        return pathHr;
    }

    HANDLE file = CreateFileW(temporaryPath, GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                              FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED |
                                  FILE_FLAG_WRITE_THROUGH,
                              nullptr);
    if (file == INVALID_HANDLE_VALUE)
    {
        const HRESULT error = HRESULT_FROM_WIN32(GetLastError());
        SecureZeroMemory(encrypted.pbData, encrypted.cbData);
        LocalFree(encrypted.pbData);
        return error;
    }
    const bool wrote = WriteAll(file, encrypted.pbData, encrypted.cbData);
    CloseHandle(file);
    SecureZeroMemory(encrypted.pbData, encrypted.cbData);
    LocalFree(encrypted.pbData);

    if (!wrote)
    {
        const DWORD error = GetLastError();
        DeleteFileW(temporaryPath);
        return HRESULT_FROM_WIN32(error ? error : ERROR_WRITE_FAULT);
    }

    if (!MoveFileExW(temporaryPath, path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
    {
        const HRESULT error = HRESULT_FROM_WIN32(GetLastError());
        DeleteFileW(temporaryPath);
        return error;
    }
    return S_OK;
}
