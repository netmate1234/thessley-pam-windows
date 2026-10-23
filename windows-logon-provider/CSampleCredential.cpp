//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
//

#ifndef WIN32_NO_STATUS
#include <ntstatus.h>
#define WIN32_NO_STATUS
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <unknwn.h>
#include <sddl.h>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include "CSampleCredential.h"
#include "guid.h"
#include "provider_diag.h"
#include "password_vault.h"

static std::string Utf8(const wchar_t *text)
{
    if (!text) return {};
    int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text, -1, nullptr, 0, nullptr, nullptr);
    if (size <= 1) return {};
    std::string out(static_cast<size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text, -1, &out[0], size, nullptr, nullptr);
    out.resize(static_cast<size_t>(size - 1));
    return out;
}

static HRESULT WindowsAccountNameFromSid(PCWSTR sidText, std::wstring &accountName)
{
    if (!sidText || !*sidText) return E_INVALIDARG;
    PSID sid = nullptr;
    if (!ConvertStringSidToSidW(sidText, &sid))
        return HRESULT_FROM_WIN32(GetLastError());

    DWORD nameLength = 0, domainLength = 0;
    SID_NAME_USE use{};
    LookupAccountSidW(nullptr, sid, nullptr, &nameLength, nullptr, &domainLength, &use);
    DWORD error = GetLastError();
    if (error != ERROR_INSUFFICIENT_BUFFER || !nameLength)
    {
        LocalFree(sid);
        return HRESULT_FROM_WIN32(error ? error : ERROR_NONE_MAPPED);
    }

    std::vector<wchar_t> name(nameLength);
    std::vector<wchar_t> domain(domainLength ? domainLength : 1);
    if (!LookupAccountSidW(nullptr, sid, name.data(), &nameLength, domain.data(), &domainLength, &use))
    {
        error = GetLastError();
        LocalFree(sid);
        return HRESULT_FROM_WIN32(error);
    }
    accountName.assign(name.data());
    LocalFree(sid);
    return accountName.empty() ? HRESULT_FROM_WIN32(ERROR_NONE_MAPPED) : S_OK;
}

static std::wstring RenderQr(const std::string &matrix)
{
    std::vector<std::string> rows;
    std::istringstream input(matrix);
    std::string row;
    while (std::getline(input, row, '/'))
    {
        if (!row.empty()) rows.push_back(row);
    }
    if (rows.empty()) return L"";
    const size_t width = rows.front().size();
    if (!width || width > 100 || rows.size() > 100) return L"";
    for (const auto &r : rows) if (r.size() != width) return L"";
    // Pair two QR rows into one block glyph. Use a light-shade glyph for the
    // white/white case instead of a space: spaces are narrower in LogonUI's
    // proportional font and make the QR columns drift. All four glyphs have
    // the same advance and are emitted as UTF-16 (no console code-page path).
    if (rows.size() % 2) rows.emplace_back(width, '0');
    std::wstring out;
    for (size_t y = 0; y < rows.size(); y += 2)
    {
        for (size_t x = 0; x < width; ++x)
        {
            const bool top = rows[y][x] == '1';
            const bool bottom = rows[y + 1][x] == '1';
            out.push_back(top ? (bottom ? L'\x2588' : L'\x2580')
                              : (bottom ? L'\x2584' : L'\x2591'));
        }
        if (y + 2 < rows.size()) out.append(L"\r\n");
    }
    return out;
}

static bool LaunchQrViewer(const std::string &matrix)
{
    if (matrix.empty() || matrix.size() > 12000) return false;
    const int chars = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, matrix.data(),
                                           static_cast<int>(matrix.size()), nullptr, 0);
    if (chars <= 0) return false;
    std::wstring wideMatrix(static_cast<size_t>(chars), L'\0');
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, matrix.data(),
                             static_cast<int>(matrix.size()), wideMatrix.data(), chars)) return false;
    const std::wstring app = L"C:\\ProgramData\\ThessleyPamWin\\credential-provider\\ThessleyQrViewer.exe";
    std::wstring command = L"\"" + app + L"\" --matrix=" + wideMatrix;
    std::vector<wchar_t> writable(command.begin(), command.end());
    writable.push_back(L'\0');
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.lpDesktop = const_cast<LPWSTR>(L"WinSta0\\Winlogon");
    PROCESS_INFORMATION process{};
    const BOOL ok = CreateProcessW(app.c_str(), writable.data(), nullptr, nullptr, FALSE,
                                   CREATE_UNICODE_ENVIRONMENT, nullptr, nullptr, &startup, &process);
    if (ok)
    {
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
    }
    return ok != FALSE;
}

static void CloseQrViewer()
{
    HWND viewer = FindWindowW(L"ThessleySignInTest", L"Thessley Passkey QR");
    if (viewer) PostMessageW(viewer, WM_CLOSE, 0, 0);
}

static bool JsonBoolTrue(const std::string &line, const char *key)
{
    const auto at = line.find(key);
    return at != std::string::npos && line.find("true", at + strlen(key)) != std::string::npos;
}

static std::string JsonString(const std::string &line, const char *key)
{
    const auto keyAt = line.find(key);
    if (keyAt == std::string::npos) return {};
    const auto colon = line.find(':', keyAt + strlen(key));
    if (colon == std::string::npos) return {};
    const auto start = line.find('"', colon + 1);
    if (start == std::string::npos) return {};
    const auto end = line.find('"', start + 1);
    if (end == std::string::npos) return {};
    return line.substr(start + 1, end - start - 1);
}

struct PasswordVectorWiper
{
    std::vector<WCHAR> &value;
    ~PasswordVectorWiper() { ThessleySecureClear(value); }
};

CSampleCredential::CSampleCredential():
    _cRef(1),
    _pFTM(nullptr),
    _pCredProvCredentialEvents(nullptr),
    _pProviderEvents(nullptr),
    _providerAdviseContext(0),
    _pszUserSid(nullptr),
    _pszQualifiedUserName(nullptr),
    _fIsLocalUser(false),
    _vaultAvailable(false),
    _passwordEntryMode(false),
    _savePasswordAfterSuccess(false),
    _fChecked(false),
    _fShowControls(false),
    _dwComboIndex(0),
    _approvalInProgress(false),
    _approvalCancelled(false),
    _phoneApproved(false),
    _approvalSocket(0)
{
    DllAddRef();
    const HRESULT marshalHr = CoCreateFreeThreadedMarshaler(
        static_cast<ICredentialProviderCredential2 *>(this), &_pFTM);
    ProviderDiag(L"CreateCredentialFTM", marshalHr, 0);

    ZeroMemory(_rgCredProvFieldDescriptors, sizeof(_rgCredProvFieldDescriptors));
    ZeroMemory(_rgFieldStatePairs, sizeof(_rgFieldStatePairs));
    ZeroMemory(_rgFieldStrings, sizeof(_rgFieldStrings));
}

CSampleCredential::~CSampleCredential()
{
    _CancelApproval();
    if (_approvalThread.joinable() && _approvalThread.get_id() != std::this_thread::get_id())
    {
        _approvalThread.join();
    }
    if (_rgFieldStrings[SFI_PASSWORD])
    {
        size_t lenPassword = wcslen(_rgFieldStrings[SFI_PASSWORD]);
        SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD], lenPassword * sizeof(*_rgFieldStrings[SFI_PASSWORD]));
    }
    for (int i = 0; i < ARRAYSIZE(_rgFieldStrings); i++)
    {
        CoTaskMemFree(_rgFieldStrings[i]);
        CoTaskMemFree(_rgCredProvFieldDescriptors[i].pszLabel);
    }
    CoTaskMemFree(_pszUserSid);
    CoTaskMemFree(_pszQualifiedUserName);
    if (_pProviderEvents) _pProviderEvents->Release();
    if (_pFTM) _pFTM->Release();
    DllRelease();
}

void CSampleCredential::SetProviderEvents(ICredentialProviderEvents *events, UINT_PTR adviseContext)
{
    std::lock_guard<std::mutex> lock(_providerEventsMutex);
    if (events) events->AddRef();
    if (_pProviderEvents) _pProviderEvents->Release();
    _pProviderEvents = events;
    _providerAdviseContext = events ? adviseContext : 0;
}

bool CSampleCredential::IsAutoLogonReady() const
{
    return _phoneApproved.load() && _vaultAvailable && !_passwordEntryMode;
}

void CSampleCredential::_CancelApproval()
{
    _approvalCancelled.store(true);
    const uintptr_t raw = _approvalSocket.exchange(0);
    if (raw)
    {
        const SOCKET sock = static_cast<SOCKET>(raw);
        shutdown(sock, SD_BOTH);
        closesocket(sock);
    }
}

void CSampleCredential::_StartApproval()
{
    if (_phoneApproved.load()) return;
    bool expected = false;
    if (!_approvalInProgress.compare_exchange_strong(expected, true)) return;

    if (_approvalThread.joinable()) _approvalThread.join();
    _approvalCancelled.store(false);
    _phoneApproved.store(false);
    ThessleySecureClear(_passwordPendingSave);
    _savePasswordAfterSuccess = false;
    if (_rgFieldStrings[SFI_EDIT_TEXT])
    {
        SecureZeroMemory(_rgFieldStrings[SFI_EDIT_TEXT], wcslen(_rgFieldStrings[SFI_EDIT_TEXT]) * sizeof(WCHAR));
        CoTaskMemFree(_rgFieldStrings[SFI_EDIT_TEXT]);
        _rgFieldStrings[SFI_EDIT_TEXT] = nullptr;
        SHStrDupW(L"Waiting for the network. The QR opens in a separate window once ready. Keep this tile selected.",
                  &_rgFieldStrings[SFI_EDIT_TEXT]);
    }
    if (_rgFieldStrings[SFI_LOGONSTATUS_TEXT])
    {
        CoTaskMemFree(_rgFieldStrings[SFI_LOGONSTATUS_TEXT]);
        _rgFieldStrings[SFI_LOGONSTATUS_TEXT] = nullptr;
        SHStrDupW(L"Waiting for the network before starting phone approval.", &_rgFieldStrings[SFI_LOGONSTATUS_TEXT]);
    }
    if (_pCredProvCredentialEvents)
    {
        _pCredProvCredentialEvents->SetFieldString(this, SFI_EDIT_TEXT, _rgFieldStrings[SFI_EDIT_TEXT]);
        _pCredProvCredentialEvents->SetFieldString(this, SFI_LOGONSTATUS_TEXT, _rgFieldStrings[SFI_LOGONSTATUS_TEXT]);
    }

    IStream *eventStream = nullptr, *credentialStream = nullptr;
    HRESULT hr = _pCredProvCredentialEvents
        ? CoMarshalInterThreadInterfaceInStream(IID_ICredentialProviderCredentialEvents2,
              _pCredProvCredentialEvents, &eventStream)
        : E_UNEXPECTED;
    ProviderDiag(L"ApprovalMarshalEvents", hr, 0);
    if (SUCCEEDED(hr))
    {
        ICredentialProviderCredential *credential = nullptr;
        hr = QueryInterface(IID_ICredentialProviderCredential, reinterpret_cast<void **>(&credential));
        if (SUCCEEDED(hr))
        {
            hr = CoMarshalInterThreadInterfaceInStream(IID_ICredentialProviderCredential,
                  credential, &credentialStream);
            credential->Release();
            ProviderDiag(L"ApprovalMarshalCredential", hr, 0);
        }
        else
        {
            ProviderDiag(L"ApprovalQueryCredential", hr, 0);
        }
    }
    if (FAILED(hr))
    {
        _approvalInProgress.store(false);
        if (eventStream) eventStream->Release();
        if (credentialStream) credentialStream->Release();
        if (_rgFieldStrings[SFI_LOGONSTATUS_TEXT])
        {
            CoTaskMemFree(_rgFieldStrings[SFI_LOGONSTATUS_TEXT]);
            _rgFieldStrings[SFI_LOGONSTATUS_TEXT] = nullptr;
            SHStrDupW(L"Could not start phone approval. Choose PIN or retry.", &_rgFieldStrings[SFI_LOGONSTATUS_TEXT]);
        }
        if (_pCredProvCredentialEvents)
            _pCredProvCredentialEvents->SetFieldString(this, SFI_LOGONSTATUS_TEXT, _rgFieldStrings[SFI_LOGONSTATUS_TEXT]);
        return;
    }

    IStream *providerEventsStream = nullptr;
    UINT_PTR providerAdviseContext = 0;
    if (_vaultAvailable && !_passwordEntryMode)
    {
        std::lock_guard<std::mutex> lock(_providerEventsMutex);
        if (_pProviderEvents)
        {
            providerAdviseContext = _providerAdviseContext;
            const HRESULT notifyHr = CoMarshalInterThreadInterfaceInStream(
                IID_ICredentialProviderEvents, _pProviderEvents, &providerEventsStream);
            ProviderDiag(L"ApprovalMarshalProviderEvents", notifyHr, 0);
        }
    }

    AddRef();
    try
    {
        _approvalThread = std::thread([this, eventStream, credentialStream,
                                       providerEventsStream, providerAdviseContext]()
        {
            CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
            ICredentialProviderCredentialEvents2 *events = nullptr;
            ICredentialProviderCredential *credential = nullptr;
            ICredentialProviderEvents *providerEvents = nullptr;
            CoGetInterfaceAndReleaseStream(eventStream, IID_ICredentialProviderCredentialEvents2,
                                           reinterpret_cast<void **>(&events));
            CoGetInterfaceAndReleaseStream(credentialStream, IID_ICredentialProviderCredential,
                                           reinterpret_cast<void **>(&credential));
            if (providerEventsStream)
                CoGetInterfaceAndReleaseStream(providerEventsStream, IID_ICredentialProviderEvents,
                                               reinterpret_cast<void **>(&providerEvents));
            auto update = [&](DWORD field, const std::wstring &value)
            {
                if (!_approvalCancelled.load() && events && credential)
                    events->SetFieldString(credential, field, value.c_str());
            };
            bool ok = false;
            WSADATA wsa{};
            if (WSAStartup(MAKEWORD(2, 2), &wsa) == 0 && !_approvalCancelled.load())
            {
                SOCKET sock = INVALID_SOCKET;
                sockaddr_in address{};
                address.sin_family = AF_INET;
                address.sin_port = htons(47800);
                inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
                // The approval task starts at boot and may wait briefly for DHCP before binding its listener.
                // Retry localhost so the first lock-screen selection still produces a QR.
                unsigned long long attempts = 0;
                while (!_approvalCancelled.load())
                {
                    SOCKET candidate = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                    if (candidate == INVALID_SOCKET) break;
                    _approvalSocket.store(static_cast<uintptr_t>(candidate));
                    if (_approvalCancelled.load())
                    {
                        _CancelApproval();
                        break;
                    }
                    if (connect(candidate, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0)
                    {
                        sock = candidate;
                        break;
                    }
                    if (_approvalSocket.exchange(0) == static_cast<uintptr_t>(candidate)) closesocket(candidate);
                    ++attempts;
                    if (attempts % 10 == 0)
                        update(SFI_LOGONSTATUS_TEXT,
                               L"Still waiting for the network. The QR will appear when it is ready.");
                    if (!_approvalCancelled.load()) Sleep(500);
                }
                if (sock != INVALID_SOCKET)
                {
                    if (_approvalCancelled.load())
                    {
                        if (_approvalSocket.exchange(0) == static_cast<uintptr_t>(sock)) closesocket(sock);
                    }
                    else
                    {
                        update(SFI_LOGONSTATUS_TEXT,
                               L"Connected. Preparing a fresh QR approval; keep this tile selected.");
                        std::wstring windowsAccount;
                        const HRESULT accountHr = WindowsAccountNameFromSid(_pszUserSid, windowsAccount);
                        ProviderDiag(L"ResolveLogonAccountFromSid", accountHr, 0);
                        std::string user = Utf8(SUCCEEDED(accountHr)
                            ? windowsAccount.c_str() : _pszQualifiedUserName);
                        std::string escaped;
                        for (char c : user)
                        {
                            if (c == '"' || c == '\\') escaped.push_back('\\');
                            if (static_cast<unsigned char>(c) < 0x20) continue;
                            escaped.push_back(c);
                        }
                        const std::string request = "{\"op\":\"windows-logon\",\"user\":\"" + escaped + "\"}\n";
                        size_t sent = 0;
                        while (sent < request.size() && !_approvalCancelled.load())
                        {
                            int n = send(sock, request.data() + sent, static_cast<int>(request.size() - sent), 0);
                            if (n <= 0) break;
                            sent += static_cast<size_t>(n);
                        }
                        std::string received, line;
                        char buffer[2048];
                        while (!_approvalCancelled.load())
                        {
                            int n = recv(sock, buffer, sizeof(buffer), 0);
                            if (n <= 0) break;
                            received.append(buffer, static_cast<size_t>(n));
                            size_t newline;
                            while ((newline = received.find('\n')) != std::string::npos)
                            {
                                line = received.substr(0, newline);
                                received.erase(0, newline + 1);
                                if (line.size() > 32768) { received.clear(); break; }
                                const std::string matrix = JsonString(line, "\"qr_matrix\"");
                                if (!matrix.empty())
                                {
                                    if (LaunchQrViewer(matrix))
                                    {
                                        update(SFI_EDIT_TEXT, L"The QR code is open in a separate window.");
                                        update(SFI_LOGONSTATUS_TEXT, L"Scan the QR code window with Thessley Passkey.");
                                    }
                                    else
                                    {
                                        update(SFI_EDIT_TEXT, L"Could not open the QR code window. Choose PIN or retry.");
                                        update(SFI_LOGONSTATUS_TEXT, L"QR window failed to open. Choose PIN or select this tile to retry.");
                                    }
                                }
                                if (JsonBoolTrue(line, "\"done\""))
                                {
                                    ok = JsonBoolTrue(line, "\"ok\"");
                                    break;
                                }
                            }
                            if (line.find("\"done\"") != std::string::npos) break;
                        }
                    }
                    if (_approvalSocket.exchange(0) == static_cast<uintptr_t>(sock)) closesocket(sock);
                }
                else if (!_approvalCancelled.load())
                {
                    update(SFI_LOGONSTATUS_TEXT,
                           L"The approval service did not start. Choose PIN or select this tile to retry.");
                }
                WSACleanup();
            }
            CloseQrViewer();
            if (ok && !_approvalCancelled.load())
            {
                _phoneApproved.store(true);
                update(SFI_LOGONSTATUS_TEXT, IsAutoLogonReady() && providerEvents
                    ? L"Phone approved. Signing in..."
                    : L"Phone approved. Select Submit to sign in.");
                if (IsAutoLogonReady() && providerEvents)
                {
                    const HRESULT changedHr = providerEvents->CredentialsChanged(providerAdviseContext);
                    ProviderDiag(L"ApprovalCredentialsChanged", changedHr, 0);
                }
            }
            else if (!_approvalCancelled.load())
            {
                update(SFI_LOGONSTATUS_TEXT, L"Approval failed or expired. Select again to retry, or choose PIN.");
            }
            _approvalInProgress.store(false);
            if (credential) credential->Release();
            if (events) events->Release();
            if (providerEvents) providerEvents->Release();
            CoUninitialize();
            Release();
        });
    }
    catch (...)
    {
        _approvalInProgress.store(false);
        eventStream->Release();
        credentialStream->Release();
        if (providerEventsStream) providerEventsStream->Release();
        Release();
        _CancelApproval();
    }
}


// Initializes one credential with the field information passed in.
// Set the value of the SFI_LARGE_TEXT field to pwzUsername.
HRESULT CSampleCredential::Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                                      _In_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR const *rgcpfd,
                                      _In_ FIELD_STATE_PAIR const *rgfsp,
                                      _In_ ICredentialProviderUser *pcpUser)
{
    HRESULT hr = S_OK;
    _cpus = cpus;

    GUID guidProvider;
    pcpUser->GetProviderID(&guidProvider);
    _fIsLocalUser = (guidProvider == Identity_LocalUserProvider);

    // Copy the field descriptors for each field. This is useful if you want to vary the field
    // descriptors based on what Usage scenario the credential was created for.
    for (DWORD i = 0; SUCCEEDED(hr) && i < ARRAYSIZE(_rgCredProvFieldDescriptors); i++)
    {
        _rgFieldStatePairs[i] = rgfsp[i];
        hr = FieldDescriptorCopy(rgcpfd[i], &_rgCredProvFieldDescriptors[i]);
    }

    // Initialize the String value of all the fields.
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Thessley Passkey", &_rgFieldStrings[SFI_LABEL]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Thessley Passkey unlock", &_rgFieldStrings[SFI_LARGE_TEXT]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Select this tile to request phone approval.", &_rgFieldStrings[SFI_EDIT_TEXT]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Select this tile to request phone approval.", &_rgFieldStrings[SFI_LOGONSTATUS_TEXT]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Submit", &_rgFieldStrings[SFI_SUBMIT_BUTTON]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Save encrypted password for QR-only sign-in", &_rgFieldStrings[SFI_CHECKBOX]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Combobox", &_rgFieldStrings[SFI_COMBOBOX]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Launch helper window", &_rgFieldStrings[SFI_LAUNCHWINDOW_LINK]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Hide additional controls", &_rgFieldStrings[SFI_HIDECONTROLS_LINK]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Set up QR-only sign-in (one-time Windows password)",
                       &_rgFieldStrings[SFI_QR_SETUP_LINK]);
    }
    if (SUCCEEDED(hr))
    {
        hr = pcpUser->GetStringValue(PKEY_Identity_QualifiedUserName, &_pszQualifiedUserName);
    }
    if (SUCCEEDED(hr))
    {
        PWSTR pszUserName;
        pcpUser->GetStringValue(PKEY_Identity_UserName, &pszUserName);
        if (pszUserName != nullptr)
        {
            wchar_t szString[256];
            StringCchPrintf(szString, ARRAYSIZE(szString), L"User Name: %s", pszUserName);
            hr = SHStrDupW(szString, &_rgFieldStrings[SFI_FULLNAME_TEXT]);
            CoTaskMemFree(pszUserName);
        }
        else
        {
            hr =  SHStrDupW(L"User Name is NULL", &_rgFieldStrings[SFI_FULLNAME_TEXT]);
        }
    }
    if (SUCCEEDED(hr))
    {
        PWSTR pszDisplayName;
        pcpUser->GetStringValue(PKEY_Identity_DisplayName, &pszDisplayName);
        if (pszDisplayName != nullptr)
        {
            wchar_t szString[256];
            StringCchPrintf(szString, ARRAYSIZE(szString), L"Display Name: %s", pszDisplayName);
            hr = SHStrDupW(szString, &_rgFieldStrings[SFI_DISPLAYNAME_TEXT]);
            CoTaskMemFree(pszDisplayName);
        }
        else
        {
            hr = SHStrDupW(L"Display Name is NULL", &_rgFieldStrings[SFI_DISPLAYNAME_TEXT]);
        }
    }
    if (SUCCEEDED(hr))
    {
        PWSTR pszLogonStatus;
        pcpUser->GetStringValue(PKEY_Identity_LogonStatusString, &pszLogonStatus);
        if (pszLogonStatus != nullptr)
        {
            wchar_t szString[256];
            StringCchPrintf(szString, ARRAYSIZE(szString), L"Logon Status: %s", pszLogonStatus);
            hr = SHStrDupW(szString, &_rgFieldStrings[SFI_LOGONSTATUS_TEXT]);
            CoTaskMemFree(pszLogonStatus);
        }
        else
        {
            hr = SHStrDupW(L"Logon Status is NULL", &_rgFieldStrings[SFI_LOGONSTATUS_TEXT]);
        }
    }

    if (SUCCEEDED(hr))
    {
        hr = pcpUser->GetSid(&_pszUserSid);
    }
    if (SUCCEEDED(hr))
    {
        // Microsoft accounts can also have a local Windows SID. Keep the password field
        // hidden for every account and use the SID-bound vault for either serialization path.
        _vaultAvailable = ThessleyPasswordVaultExists(_pszUserSid);
        _passwordEntryMode = false;
        if (_vaultAvailable)
        {
            CoTaskMemFree(_rgFieldStrings[SFI_QR_SETUP_LINK]);
            _rgFieldStrings[SFI_QR_SETUP_LINK] = nullptr;
            hr = SHStrDupW(L"Update saved QR sign-in", &_rgFieldStrings[SFI_QR_SETUP_LINK]);
        }
    }

    return hr;
}

// LogonUI calls this in order to give us a callback in case we need to notify it of anything.
HRESULT CSampleCredential::Advise(_In_ ICredentialProviderCredentialEvents *pcpce)
{
    if (_pCredProvCredentialEvents != nullptr)
    {
        _pCredProvCredentialEvents->Release();
    }
    const HRESULT hr = pcpce->QueryInterface(IID_PPV_ARGS(&_pCredProvCredentialEvents));
    ProviderDiag(L"CredentialAdviseEvents2", hr, 0);
    return hr;
}

// LogonUI calls this to tell us to release the callback.
HRESULT CSampleCredential::UnAdvise()
{
    if (_pCredProvCredentialEvents)
    {
        _pCredProvCredentialEvents->Release();
    }
    _pCredProvCredentialEvents = nullptr;
    return S_OK;
}

// LogonUI calls this function when our tile is selected (zoomed)
// If you simply want fields to show/hide based on the selected state,
// there's no need to do anything here - you can set that up in the
// field definitions. But if you want to do something
// more complicated, like change the contents of a field when the tile is
// selected, you would do it here.
HRESULT CSampleCredential::SetSelected(_Out_ BOOL *pbAutoLogon)
{
    *pbAutoLogon = FALSE;
    ProviderDiag(L"CredentialSetSelected", S_OK, 0);
    if (!_phoneApproved.load())
    {
        _StartApproval();
    }
    return S_OK;
}

// Similarly to SetSelected, LogonUI calls this when your tile was selected
// and now no longer is. The most common thing to do here (which we do below)
// is to clear out the password field.
HRESULT CSampleCredential::SetDeselected()
{
    HRESULT hr = S_OK;
    _CancelApproval();
    if (_approvalThread.joinable() && _approvalThread.get_id() != std::this_thread::get_id())
    {
        _approvalThread.join();
    }
    _phoneApproved.store(false);
    if (_rgFieldStrings[SFI_EDIT_TEXT])
    {
        SecureZeroMemory(_rgFieldStrings[SFI_EDIT_TEXT], wcslen(_rgFieldStrings[SFI_EDIT_TEXT]) * sizeof(WCHAR));
        CoTaskMemFree(_rgFieldStrings[SFI_EDIT_TEXT]);
        hr = SHStrDupW(L"Select this tile to request phone approval.", &_rgFieldStrings[SFI_EDIT_TEXT]);
        if (SUCCEEDED(hr) && _pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, SFI_EDIT_TEXT, _rgFieldStrings[SFI_EDIT_TEXT]);
        }
    }
    if (_rgFieldStrings[SFI_PASSWORD])
    {
        size_t lenPassword = wcslen(_rgFieldStrings[SFI_PASSWORD]);
        SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD], lenPassword * sizeof(*_rgFieldStrings[SFI_PASSWORD]));

        CoTaskMemFree(_rgFieldStrings[SFI_PASSWORD]);
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);

        if (SUCCEEDED(hr) && _pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, SFI_PASSWORD, _rgFieldStrings[SFI_PASSWORD]);
        }
    }

    return hr;
}

// Get info for a particular field of a tile. Called by logonUI to get information
// to display the tile.
HRESULT CSampleCredential::GetFieldState(DWORD dwFieldID,
                                         _Out_ CREDENTIAL_PROVIDER_FIELD_STATE *pcpfs,
                                         _Out_ CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE *pcpfis)
{
    HRESULT hr;

    // Validate our parameters.
    if ((dwFieldID < ARRAYSIZE(_rgFieldStatePairs)))
    {
        *pcpfs = _rgFieldStatePairs[dwFieldID].cpfs;
        *pcpfis = _rgFieldStatePairs[dwFieldID].cpfis;
        if (dwFieldID == SFI_PASSWORD)
        {
            *pcpfs = _passwordEntryMode ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN;
            *pcpfis = _passwordEntryMode ? CPFIS_FOCUSED : CPFIS_NONE;
        }
        else if (dwFieldID == SFI_CHECKBOX)
        {
            *pcpfs = _passwordEntryMode
                ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN;
        }
        else if (dwFieldID == SFI_QR_SETUP_LINK)
        {
            *pcpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
        }
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Sets ppwsz to the string value of the field at the index dwFieldID
HRESULT CSampleCredential::GetStringValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ PWSTR *ppwsz)
{
    HRESULT hr;
    *ppwsz = nullptr;

    // Check to make sure dwFieldID is a legitimate index
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors))
    {
        // Make a copy of the string and return that. The caller
        // is responsible for freeing it.
        hr = SHStrDupW(_rgFieldStrings[dwFieldID], ppwsz);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Get the image to show in the user tile
HRESULT CSampleCredential::GetBitmapValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ HBITMAP *phbmp)
{
    *phbmp = nullptr;
    HRESULT hr = E_INVALIDARG;

    if (SFI_TILEIMAGE == dwFieldID)
    {
        // Load the RT_BITMAP resource directly. LoadImage/LoadBitmap reject
        // this V4 header in LogonUI on some Windows 11 builds.
        HRSRC resource = FindResourceW(HINST_THISDLL,
                                       MAKEINTRESOURCEW(IDB_TILE_IMAGE), RT_BITMAP);
        const DWORD resourceSize = resource ? SizeofResource(HINST_THISDLL, resource) : 0;
        HGLOBAL loaded = resource ? LoadResource(HINST_THISDLL, resource) : nullptr;
        const auto *header = loaded
            ? static_cast<const BITMAPV4HEADER *>(LockResource(loaded)) : nullptr;

        if (header && resourceSize >= sizeof(BITMAPV4HEADER) &&
            header->bV4Size == sizeof(BITMAPV4HEADER) &&
            header->bV4Width > 0 && header->bV4Width <= 512 &&
            header->bV4Height != 0 && header->bV4Height >= -512 && header->bV4Height <= 512 &&
            header->bV4BitCount == 32 && header->bV4V4Compression == BI_BITFIELDS &&
            header->bV4AlphaMask != 0 && header->bV4SizeImage != 0 &&
            static_cast<ULONGLONG>(header->bV4Size) + header->bV4SizeImage <= resourceSize)
        {
            void *pixels = nullptr;
            HDC screen = GetDC(nullptr);
            HBITMAP bitmap = screen ? CreateDIBSection(
                screen, reinterpret_cast<const BITMAPINFO *>(header), DIB_RGB_COLORS,
                &pixels, nullptr, 0) : nullptr;
            if (screen) ReleaseDC(nullptr, screen);

            if (bitmap && pixels)
            {
                CopyMemory(pixels,
                           reinterpret_cast<const BYTE *>(header) + header->bV4Size,
                           header->bV4SizeImage);
                *phbmp = bitmap;
                hr = S_OK;
            }
            else
            {
                if (bitmap) DeleteObject(bitmap);
                hr = HRESULT_FROM_WIN32(GetLastError());
            }
        }
        else
        {
            hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
        }
    }

    ProviderDiag(L"GetBitmapValue", hr, dwFieldID);
    return hr;
}

// Sets pdwAdjacentTo to the index of the field the submit button should be
// adjacent to. We recommend that the submit button is placed next to the last
// field which the user is required to enter information in. Optional fields
// should be below the submit button.
HRESULT CSampleCredential::GetSubmitButtonValue(DWORD dwFieldID, _Out_ DWORD *pdwAdjacentTo)
{
    HRESULT hr;

    if (SFI_SUBMIT_BUTTON == dwFieldID)
    {
        // pdwAdjacentTo is a pointer to the fieldID you want the submit button to
        // appear next to.
        // The password field is hidden during QR-only sign-in. Keep Submit
        // beside the always-visible status field so LogonUI does not hide it.
        *pdwAdjacentTo = SFI_LOGONSTATUS_TEXT;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Sets the value of a field which can accept a string as a value.
// This is called on each keystroke when a user types into an edit field
HRESULT CSampleCredential::SetStringValue(DWORD dwFieldID, _In_ PCWSTR pwz)
{
    HRESULT hr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_EDIT_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft ||
        CPFT_PASSWORD_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        PWSTR *ppwszStored = &_rgFieldStrings[dwFieldID];
        if (dwFieldID == SFI_PASSWORD && *ppwszStored)
            SecureZeroMemory(*ppwszStored, wcslen(*ppwszStored) * sizeof(WCHAR));
        CoTaskMemFree(*ppwszStored);
        hr = SHStrDupW(pwz, ppwszStored);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Returns whether a checkbox is checked or not as well as its label.
HRESULT CSampleCredential::GetCheckboxValue(DWORD dwFieldID, _Out_ BOOL *pbChecked, _Outptr_result_nullonfailure_ PWSTR *ppwszLabel)
{
    HRESULT hr;
    *ppwszLabel = nullptr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_CHECKBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        *pbChecked = _fChecked;
        hr = SHStrDupW(_rgFieldStrings[SFI_CHECKBOX], ppwszLabel);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Sets whether the specified checkbox is checked or not.
HRESULT CSampleCredential::SetCheckboxValue(DWORD dwFieldID, BOOL bChecked)
{
    HRESULT hr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_CHECKBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        _fChecked = bChecked;
        _savePasswordAfterSuccess = _passwordEntryMode && bChecked;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Returns the number of items to be included in the combobox (pcItems), as well as the
// currently selected item (pdwSelectedItem).
HRESULT CSampleCredential::GetComboBoxValueCount(DWORD dwFieldID, _Out_ DWORD *pcItems, _Deref_out_range_(<, *pcItems) _Out_ DWORD *pdwSelectedItem)
{
    HRESULT hr;
    *pcItems = 0;
    *pdwSelectedItem = 0;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        *pcItems = ARRAYSIZE(s_rgComboBoxStrings);
        *pdwSelectedItem = 0;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Called iteratively to fill the combobox with the string (ppwszItem) at index dwItem.
HRESULT CSampleCredential::GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, _Outptr_result_nullonfailure_ PWSTR *ppwszItem)
{
    HRESULT hr;
    *ppwszItem = nullptr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        hr = SHStrDupW(s_rgComboBoxStrings[dwItem], ppwszItem);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Called when the user changes the selected item in the combobox.
HRESULT CSampleCredential::SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem)
{
    HRESULT hr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        _dwComboIndex = dwSelectedItem;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Called when the user clicks a command link.
HRESULT CSampleCredential::CommandLinkClicked(DWORD dwFieldID)
{
    HRESULT hr = S_OK;

    CREDENTIAL_PROVIDER_FIELD_STATE cpfsShow = CPFS_HIDDEN;

    // Validate parameter.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMMAND_LINK == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        HWND hwndOwner = nullptr;
        switch (dwFieldID)
        {
        case SFI_LAUNCHWINDOW_LINK:
            if (_pCredProvCredentialEvents)
            {
                _pCredProvCredentialEvents->OnCreatingWindow(&hwndOwner);
            }

            // Pop a messagebox indicating the click.
            ::MessageBox(hwndOwner, L"Command link clicked", L"Click!", 0);
            break;
        case SFI_HIDECONTROLS_LINK:
            _pCredProvCredentialEvents->BeginFieldUpdates();
            cpfsShow = _fShowControls ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN;
            _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_FULLNAME_TEXT, cpfsShow);
            _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_DISPLAYNAME_TEXT, cpfsShow);
            _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_LOGONSTATUS_TEXT, cpfsShow);
            _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_CHECKBOX, cpfsShow);
            _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_EDIT_TEXT, cpfsShow);
            _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_COMBOBOX, cpfsShow);
            _pCredProvCredentialEvents->SetFieldString(nullptr, SFI_HIDECONTROLS_LINK, _fShowControls? L"Hide additional controls" : L"Show additional controls");
            _pCredProvCredentialEvents->EndFieldUpdates();
            _fShowControls = !_fShowControls;
            break;
        case SFI_QR_SETUP_LINK:
            _passwordEntryMode = !_passwordEntryMode;
            _savePasswordAfterSuccess = _passwordEntryMode && _fChecked;
            _fChecked = _passwordEntryMode;
            if (!_passwordEntryMode && _rgFieldStrings[SFI_PASSWORD])
            {
                SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD],
                                 wcslen(_rgFieldStrings[SFI_PASSWORD]) * sizeof(WCHAR));
                CoTaskMemFree(_rgFieldStrings[SFI_PASSWORD]);
                _rgFieldStrings[SFI_PASSWORD] = nullptr;
                SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);
            }
            if (_pCredProvCredentialEvents)
            {
            _pCredProvCredentialEvents->BeginFieldUpdates();
            _pCredProvCredentialEvents->SetFieldState(this, SFI_PASSWORD,
                _passwordEntryMode ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN);
            _pCredProvCredentialEvents->SetFieldState(this, SFI_CHECKBOX,
                _passwordEntryMode ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN);
            _pCredProvCredentialEvents->SetFieldCheckbox(this, SFI_CHECKBOX, _fChecked,
                L"Save encrypted password for QR-only sign-in");
            _pCredProvCredentialEvents->SetFieldString(this, SFI_QR_SETUP_LINK,
                _passwordEntryMode ? L"Cancel password setup" :
                    (_vaultAvailable ? L"Update saved QR sign-in" :
                                       L"Set up QR-only sign-in (one-time Windows password)"));
            _pCredProvCredentialEvents->SetFieldString(this, SFI_EDIT_TEXT,
                _passwordEntryMode
                    ? L"Enter the Windows password once. After a successful sign-in it is encrypted on this PC; future sign-ins use phone approval."
                    : L"Approve this sign-in with Thessley Passkey.");
            _pCredProvCredentialEvents->EndFieldUpdates();
            }
            break;
        default:
            hr = E_INVALIDARG;
        }

    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Collect the username and password into a serialized credential for the correct usage scenario
// (logon/unlock is what's demonstrated in this sample).  LogonUI then passes these credentials
// back to the system to log on.
HRESULT CSampleCredential::GetSerialization(_Out_ CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE *pcpgsr,
                                            _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcs,
                                            _Outptr_result_maybenull_ PWSTR *ppwszOptionalStatusText,
                                            _Out_ CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon)
{
    HRESULT hr = E_UNEXPECTED;
    *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;
    ZeroMemory(pcpcs, sizeof(*pcpcs));

    // The phone approval is a one-use gate. The built-in Windows PIN/password tiles remain separate recovery paths.
    if (!_phoneApproved.load())
    {
        SHStrDupW(L"Approve this sign-in with Thessley Passkey first, or choose another Windows sign-in option.",
                  ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_WARNING;
        return S_OK;
    }

    std::vector<WCHAR> vaultPassword;
    PasswordVectorWiper wipeVaultPassword{vaultPassword};
    PCWSTR password = nullptr;

    if (_vaultAvailable && !_passwordEntryMode)
    {
        _phoneApproved.store(false);
        const HRESULT loadHr = ThessleyPasswordVaultLoad(_pszUserSid, vaultPassword);
        ProviderDiag(L"LoadLocalPasswordVault", loadHr, 0);
        if (FAILED(loadHr))
        {
            SHStrDupW(L"The saved Windows credential could not be opened. Use Update saved QR sign-in or another Windows sign-in option.",
                      ppwszOptionalStatusText);
            *pcpsiOptionalStatusIcon = CPSI_WARNING;
            return S_OK;
        }
        password = vaultPassword.data();
    }
    else if (!_passwordEntryMode)
    {
        SHStrDupW(L"Set up QR-only sign-in once, or choose another Windows sign-in option.",
                  ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_WARNING;
        return S_OK;
    }
    else if (!_rgFieldStrings[SFI_PASSWORD] || !_rgFieldStrings[SFI_PASSWORD][0])
    {
        SHStrDupW(L"Enter the Windows password to complete this sign-in.", ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_WARNING;
        return S_OK;
    }
    else
    {
        password = _rgFieldStrings[SFI_PASSWORD];
    }

    _phoneApproved.store(false); // exactly one Windows authentication attempt per phone approval
    _savePasswordAfterSuccess = _passwordEntryMode && _fChecked;
    ThessleySecureClear(_passwordPendingSave);

    // For local user, the domain and user name can be split from _pszQualifiedUserName (domain\username).
    // CredPackAuthenticationBuffer() cannot be used because it won't work with unlock scenario.
    if (_fIsLocalUser)
    {
        PWSTR pwzProtectedPassword;
        hr = ProtectIfNecessaryAndCopyPassword(const_cast<PWSTR>(password), _cpus, &pwzProtectedPassword);
        if (SUCCEEDED(hr))
        {
            PWSTR pszDomain;
            PWSTR pszUsername;
            hr = SplitDomainAndUsername(_pszQualifiedUserName, &pszDomain, &pszUsername);
            if (SUCCEEDED(hr))
            {
                KERB_INTERACTIVE_UNLOCK_LOGON kiul;
                hr = KerbInteractiveUnlockLogonInit(pszDomain, pszUsername, pwzProtectedPassword, _cpus, &kiul);
                if (SUCCEEDED(hr))
                {
                    // We use KERB_INTERACTIVE_UNLOCK_LOGON in both unlock and logon scenarios.  It contains a
                    // KERB_INTERACTIVE_LOGON to hold the creds plus a LUID that is filled in for us by Winlogon
                    // as necessary.
                    hr = KerbInteractiveUnlockLogonPack(kiul, &pcpcs->rgbSerialization, &pcpcs->cbSerialization);
                    if (SUCCEEDED(hr))
                    {
                        ULONG ulAuthPackage;
                        hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);
                        if (SUCCEEDED(hr))
                        {
                            pcpcs->ulAuthenticationPackage = ulAuthPackage;
                            pcpcs->clsidCredentialProvider = CLSID_Thessley;
                            // At this point the credential has created the serialized credential used for logon
                            // By setting this to CPGSR_RETURN_CREDENTIAL_FINISHED we are letting logonUI know
                            // that we have all the information we need and it should attempt to submit the
                            // serialized credential.
                            *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
                        }
                    }
                }
                CoTaskMemFree(pszDomain);
                CoTaskMemFree(pszUsername);
            }
            SecureZeroMemory(pwzProtectedPassword, wcslen(pwzProtectedPassword) * sizeof(WCHAR));
            CoTaskMemFree(pwzProtectedPassword);
        }
    }
    else
    {
        DWORD dwAuthFlags = CRED_PACK_PROTECTED_CREDENTIALS | CRED_PACK_ID_PROVIDER_CREDENTIALS;

        // First get the size of the authentication buffer to allocate
        if (!CredPackAuthenticationBuffer(dwAuthFlags, _pszQualifiedUserName, const_cast<PWSTR>(password), nullptr, &pcpcs->cbSerialization) &&
            (GetLastError() == ERROR_INSUFFICIENT_BUFFER))
        {
            pcpcs->rgbSerialization = static_cast<byte *>(CoTaskMemAlloc(pcpcs->cbSerialization));
            if (pcpcs->rgbSerialization != nullptr)
            {
                hr = S_OK;

                // Retrieve the authentication buffer
                if (CredPackAuthenticationBuffer(dwAuthFlags, _pszQualifiedUserName, const_cast<PWSTR>(password), pcpcs->rgbSerialization, &pcpcs->cbSerialization))
                {
                    ULONG ulAuthPackage;
                    hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);
                    if (SUCCEEDED(hr))
                    {
                        pcpcs->ulAuthenticationPackage = ulAuthPackage;
                        pcpcs->clsidCredentialProvider = CLSID_Thessley;

                        // At this point the credential has created the serialized credential used for logon
                        // By setting this to CPGSR_RETURN_CREDENTIAL_FINISHED we are letting logonUI know
                        // that we have all the information we need and it should attempt to submit the
                        // serialized credential.
                        *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
                    }
                }
                else
                {
                    hr = HRESULT_FROM_WIN32(GetLastError());
                    if (SUCCEEDED(hr))
                    {
                        hr = E_FAIL;
                    }
                }

                if (FAILED(hr))
                {
                    CoTaskMemFree(pcpcs->rgbSerialization);
                }
            }
            else
            {
                hr = E_OUTOFMEMORY;
            }
        }
    }

    if (SUCCEEDED(hr) && *pcpgsr == CPGSR_RETURN_CREDENTIAL_FINISHED && _savePasswordAfterSuccess)
    {
        const size_t chars = wcslen(password) + 1;
        _passwordPendingSave.assign(password, password + chars);
    }
    else
    {
        _savePasswordAfterSuccess = false;
    }
    return hr;
}

struct REPORT_RESULT_STATUS_INFO
{
    NTSTATUS ntsStatus;
    NTSTATUS ntsSubstatus;
    PWSTR     pwzMessage;
    CREDENTIAL_PROVIDER_STATUS_ICON cpsi;
};

static const REPORT_RESULT_STATUS_INFO s_rgLogonStatusInfo[] =
{
    { STATUS_LOGON_FAILURE, STATUS_SUCCESS, L"Incorrect password or username.", CPSI_ERROR, },
    { STATUS_ACCOUNT_RESTRICTION, STATUS_ACCOUNT_DISABLED, L"The account is disabled.", CPSI_WARNING },
};

// ReportResult is completely optional.  Its purpose is to allow a credential to customize the string
// and the icon displayed in the case of a logon failure.  For example, we have chosen to
// customize the error shown in the case of bad username/password and in the case of the account
// being disabled.
HRESULT CSampleCredential::ReportResult(NTSTATUS ntsStatus,
                                        NTSTATUS ntsSubstatus,
                                        _Outptr_result_maybenull_ PWSTR *ppwszOptionalStatusText,
                                        _Out_ CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon)
{
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;

    if (ntsStatus == STATUS_SUCCESS && !_passwordPendingSave.empty())
    {
        const HRESULT saveHr = ThessleyPasswordVaultSave(_pszUserSid, _passwordPendingSave.data());
        ProviderDiag(L"SaveLocalPasswordVault", saveHr, 0);
        if (SUCCEEDED(saveHr))
        {
            _vaultAvailable = true;
            _passwordEntryMode = false;
            if (_rgFieldStrings[SFI_QR_SETUP_LINK])
            {
                SecureZeroMemory(_rgFieldStrings[SFI_QR_SETUP_LINK],
                    wcslen(_rgFieldStrings[SFI_QR_SETUP_LINK]) * sizeof(WCHAR));
                CoTaskMemFree(_rgFieldStrings[SFI_QR_SETUP_LINK]);
                _rgFieldStrings[SFI_QR_SETUP_LINK] = nullptr;
                SHStrDupW(L"Update saved QR sign-in", &_rgFieldStrings[SFI_QR_SETUP_LINK]);
            }
        }
        else
        {
            SHStrDupW(L"Windows sign-in succeeded, but QR setup could not be saved. Select Update saved QR sign-in to retry.",
                      ppwszOptionalStatusText);
            *pcpsiOptionalStatusIcon = CPSI_WARNING;
        }
    }
    ThessleySecureClear(_passwordPendingSave);
    _savePasswordAfterSuccess = false;

    DWORD dwStatusInfo = (DWORD)-1;

    // Look for a match on status and substatus.
    for (DWORD i = 0; i < ARRAYSIZE(s_rgLogonStatusInfo); i++)
    {
        if (s_rgLogonStatusInfo[i].ntsStatus == ntsStatus && s_rgLogonStatusInfo[i].ntsSubstatus == ntsSubstatus)
        {
            dwStatusInfo = i;
            break;
        }
    }

    if (!*ppwszOptionalStatusText && (DWORD)-1 != dwStatusInfo)
    {
        if (SUCCEEDED(SHStrDupW(s_rgLogonStatusInfo[dwStatusInfo].pwzMessage, ppwszOptionalStatusText)))
        {
            *pcpsiOptionalStatusIcon = s_rgLogonStatusInfo[dwStatusInfo].cpsi;
        }
    }

    if (ntsStatus == STATUS_LOGON_FAILURE && _vaultAvailable && !_passwordEntryMode)
    {
        _passwordEntryMode = true;
        _fChecked = TRUE;
        if (_pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->BeginFieldUpdates();
            _pCredProvCredentialEvents->SetFieldState(this, SFI_PASSWORD, CPFS_DISPLAY_IN_SELECTED_TILE);
            _pCredProvCredentialEvents->SetFieldState(this, SFI_CHECKBOX, CPFS_DISPLAY_IN_SELECTED_TILE);
            _pCredProvCredentialEvents->SetFieldCheckbox(this, SFI_CHECKBOX, TRUE,
                L"Save encrypted password for QR-only sign-in");
            _pCredProvCredentialEvents->SetFieldString(this, SFI_EDIT_TEXT,
                L"The saved password was rejected. Enter the current Windows password to update QR-only sign-in.");
            _pCredProvCredentialEvents->SetFieldString(this, SFI_QR_SETUP_LINK, L"Cancel password update");
            _pCredProvCredentialEvents->EndFieldUpdates();
        }
    }

    // If we failed the logon, erase any typed password promptly.
    if (FAILED(HRESULT_FROM_NT(ntsStatus)))
    {
        if (_pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, SFI_PASSWORD, L"");
        }
        if (_rgFieldStrings[SFI_PASSWORD])
        {
            SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD], wcslen(_rgFieldStrings[SFI_PASSWORD]) * sizeof(WCHAR));
            CoTaskMemFree(_rgFieldStrings[SFI_PASSWORD]);
            _rgFieldStrings[SFI_PASSWORD] = nullptr;
            SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);
        }
        if (_pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, SFI_LOGONSTATUS_TEXT,
                _passwordEntryMode
                    ? L"Password was not accepted. Check it and submit again, or choose PIN."
                    : L"Sign-in failed. Request fresh phone approval, or choose PIN.");
        }
        _StartApproval();
    }

    // Since nullptr is a valid value for *ppwszOptionalStatusText and *pcpsiOptionalStatusIcon
    // this function can't fail.
    return S_OK;
}

// Gets the SID of the user corresponding to the credential.
HRESULT CSampleCredential::GetUserSid(_Outptr_result_nullonfailure_ PWSTR *ppszSid)
{
    *ppszSid = nullptr;
    HRESULT hr = E_UNEXPECTED;
    if (_pszUserSid != nullptr)
    {
        hr = SHStrDupW(_pszUserSid, ppszSid);
    }
    // Return S_FALSE with a null SID in ppszSid for the
    // credential to be associated with an empty user tile.

    return hr;
}

// GetFieldOptions to enable the password reveal button and touch keyboard auto-invoke in the password field.
HRESULT CSampleCredential::GetFieldOptions(DWORD dwFieldID,
                                           _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS *pcpcfo)
{
    *pcpcfo = CPCFO_NONE;

    if (dwFieldID == SFI_PASSWORD)
    {
        *pcpcfo = CPCFO_ENABLE_PASSWORD_REVEAL;
    }
    else if (dwFieldID == SFI_TILEIMAGE)
    {
        *pcpcfo = CPCFO_ENABLE_TOUCH_KEYBOARD_AUTO_INVOKE;
    }

    return S_OK;
}
