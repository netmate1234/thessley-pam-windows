#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <algorithm>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <memory>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include "resource.h"

namespace {
constexpr UINT WM_STATUS = WM_APP + 1;
constexpr UINT WM_MATRIX = WM_APP + 2;
constexpr UINT WM_CODE = WM_APP + 5;
constexpr UINT WM_FINISH = WM_APP + 3;
constexpr UINT WM_ASK = WM_APP + 4;
constexpr int ID_START = 1001;
constexpr int ID_CANCEL = 1002;
constexpr int ID_ENROLL = 1003;
constexpr int ID_YES = 1004;
constexpr int ID_NO = 1005;
HWND g_window, g_status, g_qr, g_code, g_start, g_enroll, g_cancel, g_prompt, g_yes, g_no, g_logo;
std::atomic<SOCKET> g_socket{INVALID_SOCKET};
std::atomic<bool> g_busy{false};
std::atomic<bool> g_cancelled{false};
std::wstring g_matrix;
HFONT g_font, g_code_font;
bool g_close_when_done = false;
bool g_enrolling = false;
bool g_viewer_only = false;
std::mutex g_answer_mutex;
std::condition_variable g_answer_ready;
bool g_answer_received = false;
std::string g_answer;

void layout_viewer(HWND hwnd) {
    if (!g_viewer_only || !g_logo || !g_status || !g_qr) return;
    RECT client{};
    GetClientRect(hwnd, &client);
    const int width = client.right - client.left;
    const int height = client.bottom - client.top;
    const int margin = std::max(8, std::min(16, width / 24));
    const int statusHeight = 44;
    const int statusY = margin;
    const int qrTop = statusY + statusHeight + margin;
    const int availableWidth = std::max(1, width - margin * 2);
    const int availableHeight = std::max(1, height - qrTop - margin);
    const int side = std::min(availableWidth, availableHeight);
    const int qrX = (width - side) / 2;
    constexpr int logoSide = 32;
    constexpr int logoGap = 8;
    const int statusX = margin + logoSide + logoGap;
    MoveWindow(g_logo, margin, statusY + (statusHeight - logoSide) / 2, logoSide, logoSide, TRUE);
    MoveWindow(g_status, statusX, statusY, std::max(1, width - statusX - margin), statusHeight, TRUE);
    MoveWindow(g_qr, qrX, qrTop, side, side, TRUE);
    // The QR surface paints directly from g_matrix. Force a fresh paint after
    // every layout change so the symbol follows the viewer's current size.
    InvalidateRect(g_qr, nullptr, TRUE);
}

std::wstring current_user() {
    DWORD n = 0;
    GetUserNameW(nullptr, &n);
    std::wstring value(n, L'\0');
    if (!GetUserNameW(value.data(), &n)) return {};
    value.resize(n ? n - 1 : 0);
    return value;
}

std::string utf8(const std::wstring& value) {
    if (value.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string out(n > 0 ? n : 0, '\0');
    if (n > 1) { WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, out.data(), n, nullptr, nullptr); out.resize(n - 1); }
    return out;
}

std::wstring wide(const std::string& value) {
    if (value.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, nullptr, 0);
    std::wstring out(n > 0 ? n : 0, L'\0');
    if (n > 1) { MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, out.data(), n); out.resize(n - 1); }
    return out;
}

std::string json_escape(const std::string& value) {
    std::string out;
    for (unsigned char c : value) {
        if (c == '"' || c == '\\') { out.push_back('\\'); out.push_back((char)c); }
        else if (c >= 0x20) out.push_back((char)c);
    }
    return out;
}

std::string json_string(const std::string& line, const char* key) {
    std::string needle = std::string("\"") + key + "\"";
    auto p = line.find(needle);
    if (p == std::string::npos) return {};
    p += needle.size();
    while (p < line.size() && (line[p] == ' ' || line[p] == '\t' || line[p] == '\r' || line[p] == '\n')) ++p;
    if (p >= line.size() || line[p++] != ':') return {};
    while (p < line.size() && (line[p] == ' ' || line[p] == '\t' || line[p] == '\r' || line[p] == '\n')) ++p;
    if (p >= line.size() || line[p++] != '"') return {};
    std::string out;
    bool escaped = false;
    for (; p < line.size(); ++p) {
        char c = line[p];
        if (escaped) { out.push_back(c); escaped = false; }
        else if (c == '\\') escaped = true;
        else if (c == '"') break;
        else out.push_back(c);
    }
    return out;
}

void post_text(UINT msg, std::wstring text) {
    auto* value = new std::wstring(std::move(text));
    if (!PostMessageW(g_window, msg, 0, (LPARAM)value)) delete value;
}

void request_operation(bool enroll) {
    bool expected = false;
    if (!g_busy.compare_exchange_strong(expected, true)) return;
    g_cancelled.store(false);
    g_enrolling = enroll;
    EnableWindow(g_start, FALSE);
    EnableWindow(g_enroll, FALSE);
    SetWindowTextW(g_status, enroll ? L"Starting phone enrollment for this Windows account…" : L"Requesting phone approval…");
    g_matrix.clear();
    InvalidateRect(g_qr, nullptr, TRUE);
    std::thread([] {
        WSADATA data{};
        if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
            post_text(WM_STATUS, L"Could not start Windows networking.");
            PostMessageW(g_window, WM_FINISH, 0, 0); return;
        }
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        g_socket.store(s);
        if (g_cancelled.load() && s != INVALID_SOCKET) shutdown(s, SD_BOTH);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(47800);
        InetPtonW(AF_INET, L"127.0.0.1", &address.sin_addr);
        if (s == INVALID_SOCKET || connect(s, (sockaddr*)&address, sizeof(address)) == SOCKET_ERROR) {
            if (s != INVALID_SOCKET) closesocket(s);
            g_socket.store(INVALID_SOCKET); WSACleanup();
            post_text(WM_STATUS, L"Thessley service is unavailable on this PC.");
            PostMessageW(g_window, WM_FINISH, 0, 0); return;
        }
        std::string user = json_escape(utf8(current_user()));
        std::string request = std::string("{\"op\":\"") + (g_enrolling ? "enroll" : "windows-logon-test") +
                              "\",\"user\":\"" + user + "\"}\n";
        send(s, request.c_str(), (int)request.size(), 0);
        std::string pending;
        char buffer[2048];
        bool final_ok = false;
        for (;;) {
            int n = recv(s, buffer, sizeof(buffer), 0);
            if (n <= 0) break;
            pending.append(buffer, n);
            size_t end;
            while ((end = pending.find('\n')) != std::string::npos) {
                std::string line = pending.substr(0, end);
                pending.erase(0, end + 1);
                auto say = json_string(line, "say");
                if (!say.empty() && say.rfind("    Code:  ", 0) == 0) {
                    post_text(WM_CODE, wide(say.substr(11)));
                    post_text(WM_STATUS, L"Phone scanned the QR. Compare the code below with the phone.");
                } else if (!say.empty() && say.find_first_of("\xE2\x96\x88\xE2\x96\x84\xE2\x96\x80") == std::string::npos
                    && say.rfind("Link: ", 0) != 0) post_text(WM_STATUS, wide(say));
                auto matrix = json_string(line, "qr_matrix");
                if (!matrix.empty()) post_text(WM_MATRIX, wide(matrix));
                auto ask = json_string(line, "ask");
                if (!ask.empty()) {
                    {
                        std::lock_guard<std::mutex> lock(g_answer_mutex);
                        g_answer_received = false;
                        g_answer.clear();
                    }
                    post_text(WM_ASK, wide(ask));
                    std::unique_lock<std::mutex> lock(g_answer_mutex);
                    bool answered = g_answer_ready.wait_for(lock, std::chrono::seconds(190), [] {
                        return g_answer_received || g_cancelled.load();
                    });
                    std::string answer = answered && g_answer_received ? g_answer : "no";
                    lock.unlock();
                    std::string reply = std::string("{\"answer\":\"") + answer + "\"}\n";
                    send(s, reply.c_str(), (int)reply.size(), 0);
                }
                if (line.find("\"done\": true") != std::string::npos) {
                    final_ok = line.find("\"ok\": true") != std::string::npos;
                    const wchar_t* result = g_enrolling
                        ? (final_ok ? L"Phone added to this account. You can now request an approval QR." : L"Enrollment refused, denied, or timed out.")
                        : (final_ok ? L"Phone approval received. This test did not sign you in or change Windows login." : L"Request refused, denied, or timed out.");
                    post_text(WM_STATUS, result);
                    PostMessageW(g_window, WM_FINISH, 0, 0);
                    closesocket(s); g_socket.store(INVALID_SOCKET); WSACleanup(); return;
                }
            }
        }
        closesocket(s); g_socket.store(INVALID_SOCKET); WSACleanup();
        if (!g_busy.load()) post_text(WM_STATUS, L"Request cancelled.");
        else post_text(WM_STATUS, L"Connection closed before approval completed.");
        PostMessageW(g_window, WM_FINISH, 0, 0);
    }).detach();
}

void cancel_request() {
    g_cancelled.store(true);
    g_answer_ready.notify_all();
    SOCKET s = g_socket.load();
    if (s != INVALID_SOCKET) shutdown(s, SD_BOTH);
    SetWindowTextW(g_status, L"Cancelling request…");
}

LRESULT CALLBACK qr_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_SIZE) {
        InvalidateRect(hwnd, nullptr, TRUE);
        return 0;
    }
    if (msg == WM_PAINT) {
        PAINTSTRUCT ps{}; HDC dc = BeginPaint(hwnd, &ps);
        RECT r{}; GetClientRect(hwnd, &r);
        FillRect(dc, &r, (HBRUSH)GetStockObject(WHITE_BRUSH));
        std::vector<std::wstring> rows;
        size_t pos = 0;
        while (pos <= g_matrix.size()) {
            size_t end = g_matrix.find(L'/', pos);
            if (end == std::wstring::npos) end = g_matrix.size();
            if (end > pos) rows.emplace_back(g_matrix.substr(pos, end - pos));
            if (end == g_matrix.size()) break;
            pos = end + 1;
        }
        // The sign-in service intentionally supplies a two-module quiet zone.
        // Preserve it; trimming four modules cuts into the QR data and makes the
        // symbol appear cropped/overflowing on the lock screen.
        constexpr size_t trim = 0;
        if (rows.size() > trim * 2 && rows.front().size() > trim * 2) {
            const size_t qrWidth = rows.front().size();
            bool square = true;
            for (const auto &row : rows) if (row.size() != qrWidth) { square = false; break; }
            if (square) {
                rows.erase(rows.begin(), rows.begin() + trim);
                rows.erase(rows.end() - trim, rows.end());
                for (auto &row : rows) row = row.substr(trim, qrWidth - trim * 2);
            }
        }
        const int count = (int)rows.size();
        bool valid = count > 0;
        for (const auto &row : rows) {
            if ((int)row.size() != count) { valid = false; break; }
            for (wchar_t bit : row) if (bit != L'0' && bit != L'1') { valid = false; break; }
            if (!valid) break;
        }
        if (valid) {
            // Map each module edge independently to the available square.
            // Unlike flooring one integer cell size, this fills the whole QR
            // area at every window size without dropping edge modules.
            const int width = static_cast<int>(r.right - r.left);
            const int height = static_cast<int>(r.bottom - r.top);
            const int side = std::max(0, std::min(width, height));
            const int x0 = static_cast<int>(r.left) + (width - side) / 2;
            const int y0 = static_cast<int>(r.top) + (height - side) / 2;
            HBRUSH black = (HBRUSH)GetStockObject(BLACK_BRUSH);
            for (int y = 0; y < count; ++y) {
                const int top = y0 + (y * side) / count;
                const int bottom = y0 + ((y + 1) * side) / count;
                for (int x = 0; x < count; ++x) if (rows[y][x] == L'1') {
                    const int left = x0 + (x * side) / count;
                    const int right = x0 + ((x + 1) * side) / count;
                    RECT module{left, top, right, bottom};
                    FillRect(dc, &module, black);
                }
            }
        } else {
            SetBkMode(dc, TRANSPARENT); SetTextColor(dc, RGB(100,100,100));
            DrawTextW(dc, g_matrix.empty() ? L"QR code appears here" : L"Waiting for complete QR data…",
                      -1, &r, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        }
        EndPaint(hwnd, &ps); return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

LRESULT CALLBACK main_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CTLCOLORSTATIC:
        if (g_viewer_only && (HWND)lp == g_status) {
            HDC dc = (HDC)wp;
            SetBkColor(dc, RGB(255, 255, 255));
            SetTextColor(dc, RGB(32, 32, 32));
            return (LRESULT)GetStockObject(WHITE_BRUSH);
        }
        break;
    case WM_SIZE:
        if (g_viewer_only) {
            layout_viewer(hwnd);
            return 0;
        }
        break;
    case WM_GETMINMAXINFO:
        if (g_viewer_only) {
            auto *limits = reinterpret_cast<MINMAXINFO*>(lp);
            limits->ptMinTrackSize.x = 280;
            limits->ptMinTrackSize.y = 340;
            return 0;
        }
        break;
    case WM_KEYDOWN:
        if (g_viewer_only && wp == VK_ESCAPE) { DestroyWindow(hwnd); return 0; }
        break;
    case WM_CREATE: {
        g_window = hwnd;
        g_font = CreateFontW(18,0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Segoe UI");
        if (g_viewer_only) {
            g_logo = CreateWindowW(L"STATIC", L"", WS_CHILD|WS_VISIBLE|SS_BITMAP, 14, 12, 32, 32, hwnd, nullptr, nullptr, nullptr);
            SendMessageW(g_logo, STM_SETIMAGE, IMAGE_BITMAP,
                         (LPARAM)LoadBitmapW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(IDB_BRAND_IMAGE)));
            g_status = CreateWindowW(L"STATIC", L"Scan this QR code with Thessley Passkey.", WS_CHILD|WS_VISIBLE|SS_LEFT|SS_CENTERIMAGE|SS_EDITCONTROL, 54, 10, 420, 44, hwnd, nullptr, nullptr, nullptr);
            g_qr = CreateWindowW(L"ThessleyQrSurface", L"", WS_CHILD|WS_VISIBLE, 15, 50, 450, 450, hwnd, nullptr, nullptr, nullptr);
            SendMessageW(g_status, WM_SETFONT, (WPARAM)g_font, TRUE);
            layout_viewer(hwnd);
            return 0;
        }
        std::wstring intro = L"Signed-in Windows account: " + current_user() + L". This app does not sign you in.";
        g_logo = CreateWindowW(L"STATIC", L"", WS_CHILD|WS_VISIBLE|SS_BITMAP, 18, 18, 32, 32, hwnd, nullptr, nullptr, nullptr);
        SendMessageW(g_logo, STM_SETIMAGE, IMAGE_BITMAP,
                     (LPARAM)LoadBitmapW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(IDB_BRAND_IMAGE)));
        g_status = CreateWindowW(L"STATIC", intro.c_str(), WS_CHILD|WS_VISIBLE|SS_LEFT|SS_CENTERIMAGE, 60, 12, 468, 50, hwnd, nullptr, nullptr, nullptr);
        g_qr = CreateWindowW(L"ThessleyQrSurface", L"", WS_CHILD|WS_VISIBLE, 60, 68, 420, 420, hwnd, nullptr, nullptr, nullptr);
        g_code = CreateWindowW(L"STATIC", L"", WS_CHILD|WS_VISIBLE|SS_CENTER, 18, 492, 510, 38, hwnd, nullptr, nullptr, nullptr);
        g_start = CreateWindowW(L"BUTTON", L"Request phone approval", WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON, 18, 536, 246, 36, hwnd, (HMENU)ID_START, nullptr, nullptr);
        g_enroll = CreateWindowW(L"BUTTON", L"Enroll this account", WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON, 278, 536, 246, 36, hwnd, (HMENU)ID_ENROLL, nullptr, nullptr);
        g_prompt = CreateWindowW(L"STATIC", L"", WS_CHILD|SS_LEFT, 18, 578, 510, 34, hwnd, nullptr, nullptr, nullptr);
        g_yes = CreateWindowW(L"BUTTON", L"Yes, codes match", WS_CHILD|BS_PUSHBUTTON, 18, 618, 180, 36, hwnd, (HMENU)ID_YES, nullptr, nullptr);
        g_no = CreateWindowW(L"BUTTON", L"No, cancel", WS_CHILD|BS_PUSHBUTTON, 208, 618, 130, 36, hwnd, (HMENU)ID_NO, nullptr, nullptr);
        g_cancel = CreateWindowW(L"BUTTON", L"Cancel request", WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON, 348, 618, 176, 36, hwnd, (HMENU)ID_CANCEL, nullptr, nullptr);
        SendMessageW(g_status, WM_SETFONT, (WPARAM)g_font, TRUE);
        g_code_font = CreateFontW(30,0,0,0,FW_BOLD,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Segoe UI");
        SendMessageW(g_code, WM_SETFONT, (WPARAM)g_code_font, TRUE);
        SendMessageW(g_start, WM_SETFONT, (WPARAM)g_font, TRUE); SendMessageW(g_enroll, WM_SETFONT, (WPARAM)g_font, TRUE);
        SendMessageW(g_prompt, WM_SETFONT, (WPARAM)g_font, TRUE); SendMessageW(g_yes, WM_SETFONT, (WPARAM)g_font, TRUE);
        SendMessageW(g_no, WM_SETFONT, (WPARAM)g_font, TRUE); SendMessageW(g_cancel, WM_SETFONT, (WPARAM)g_font, TRUE);
        ShowWindow(g_yes, SW_HIDE); ShowWindow(g_no, SW_HIDE);
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == ID_START) { request_operation(false); return 0; }
        if (LOWORD(wp) == ID_ENROLL) { request_operation(true); return 0; }
        if (LOWORD(wp) == ID_CANCEL) { cancel_request(); return 0; }
        if (LOWORD(wp) == ID_YES || LOWORD(wp) == ID_NO) {
            { std::lock_guard<std::mutex> lock(g_answer_mutex); g_answer = LOWORD(wp) == ID_YES ? "yes" : "no"; g_answer_received = true; }
            g_answer_ready.notify_one();
            ShowWindow(g_prompt, SW_HIDE); ShowWindow(g_yes, SW_HIDE); ShowWindow(g_no, SW_HIDE);
            return 0;
        }
        break;
    case WM_STATUS: case WM_MATRIX: case WM_CODE: {
        std::unique_ptr<std::wstring> value((std::wstring*)lp);
        if (msg == WM_STATUS) SetWindowTextW(g_status, value->c_str());
        else if (msg == WM_MATRIX) { g_matrix = *value; InvalidateRect(g_qr,nullptr,TRUE); }
        else SetWindowTextW(g_code, value->c_str());
        return 0;
    }
    case WM_ASK: {
        std::unique_ptr<std::wstring> value((std::wstring*)lp);
        SetWindowTextW(g_prompt, value->c_str());
        ShowWindow(g_prompt, SW_SHOW); ShowWindow(g_yes, SW_SHOW); ShowWindow(g_no, SW_SHOW);
        return 0;
    }
    case WM_FINISH:
        g_busy.store(false); EnableWindow(g_start, TRUE); EnableWindow(g_enroll, TRUE);
        ShowWindow(g_prompt, SW_HIDE); ShowWindow(g_yes, SW_HIDE); ShowWindow(g_no, SW_HIDE);
        if(g_close_when_done) DestroyWindow(hwnd);
        return 0;
    case WM_CLOSE: if(g_busy.load()){g_close_when_done=true;cancel_request();}else DestroyWindow(hwnd); return 0;
    case WM_DESTROY:
        { SOCKET s=g_socket.load(); if(s!=INVALID_SOCKET) shutdown(s,SD_BOTH); }
        if (g_font) DeleteObject(g_font);
        if (g_code_font) DeleteObject(g_code_font);
        PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(hwnd,msg,wp,lp);
}
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR command, int show) {
    if (command) {
        const std::wstring args(command);
        const auto at = args.find(L"--matrix=");
        if (at != std::wstring::npos) {
            size_t start = at + 9, end = args.find_first_of(L" \t\r\n", start);
            g_matrix = args.substr(start, end == std::wstring::npos ? end : end - start);
            g_viewer_only = !g_matrix.empty();
        }
    }
    if (g_viewer_only) {
        HWND existing = FindWindowW(L"ThessleySignInTest", L"Thessley Passkey QR");
        if (existing) {
            DWORD_PTR result = 0;
            SendMessageTimeoutW(existing, WM_CLOSE, 0, 0, SMTO_ABORTIFHUNG, 1000, &result);
            for (int attempt = 0; attempt < 20 && FindWindowW(L"ThessleySignInTest", L"Thessley Passkey QR"); ++attempt)
                Sleep(50);
        }
    }
    HICON appIcon = LoadIconW(instance, MAKEINTRESOURCEW(IDI_THESSLEY));
    WNDCLASSW qr{}; qr.lpfnWndProc=qr_proc; qr.hInstance=instance; qr.lpszClassName=L"ThessleyQrSurface"; qr.hCursor=LoadCursor(nullptr,IDC_ARROW); qr.hbrBackground=(HBRUSH)(COLOR_WINDOW+1); RegisterClassW(&qr);
    WNDCLASSW wc{}; wc.lpfnWndProc=main_proc; wc.hInstance=instance; wc.hIcon=appIcon; wc.lpszClassName=L"ThessleySignInTest"; wc.hCursor=LoadCursor(nullptr,IDC_ARROW); wc.hbrBackground=(HBRUSH)(COLOR_WINDOW+1); RegisterClassW(&wc);
    const wchar_t *title = g_viewer_only ? L"Thessley Passkey QR" : L"Thessley Windows sign-in test";
    const int width = g_viewer_only ? 500 : 560, height = g_viewer_only ? 600 : 740;
    int x = CW_USEDEFAULT, y = CW_USEDEFAULT;
    if (g_viewer_only) {
        RECT workArea{};
        if (SystemParametersInfoW(SPI_GETWORKAREA, 0, &workArea, 0)) {
            x = workArea.left;
            y = workArea.top;
        }
    }
    DWORD style = WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX;
    if (g_viewer_only) style |= WS_THICKFRAME|WS_MAXIMIZEBOX;
    HWND hwnd=CreateWindowW(wc.lpszClassName,title,style,x,y,width,height,nullptr,nullptr,instance,nullptr);
    if(!hwnd) return 1;
    SendMessageW(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)appIcon);
    ShowWindow(hwnd,show); UpdateWindow(hwnd);
    if (g_viewer_only) SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE|SWP_NOSIZE|SWP_SHOWWINDOW);
    MSG msg; while(GetMessageW(&msg,nullptr,0,0)>0){TranslateMessage(&msg);DispatchMessageW(&msg);} return (int)msg.wParam;
}
