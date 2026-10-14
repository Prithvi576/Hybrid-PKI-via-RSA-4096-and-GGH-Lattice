
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "crypto_api.hpp"
#include "../machines/machine_manager.hpp"
#include "../messaging/message_store.hpp"
#include "../networking/sender_network.hpp"
#include "../storage/local_storage.hpp"
#include <commctrl.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using namespace std;

namespace {

// Control IDs
constexpr int kSearchEdit = 201;
constexpr int kAddMachine = 202;
constexpr int kDeleteMachine = 203;
constexpr int kMachineList = 204;
constexpr int kGenRsa = 205;
constexpr int kGenGgh = 206;
constexpr int kCommandEdit = 207;
constexpr int kSendCommand = 208;
constexpr int kEditMachine = 209;
constexpr UINT_PTR kClockTimer = 1;
constexpr UINT kAsyncSendDone = WM_USER + 100;

// Color palette - dark modern theme
constexpr COLORREF kBgDeep = RGB(17, 27, 33);
constexpr COLORREF kBgSidebar = RGB(18, 28, 33);
constexpr COLORREF kBgChat = RGB(11, 20, 27);
constexpr COLORREF kBgCard = RGB(30, 44, 52);
constexpr COLORREF kBgField = RGB(42, 57, 66);
constexpr COLORREF kBgBubbleOut = RGB(0, 92, 75);
constexpr COLORREF kBgBubbleIn = RGB(30, 44, 52);
constexpr COLORREF kTextBright = RGB(233, 237, 239);
constexpr COLORREF kTextMuted = RGB(134, 150, 160);
constexpr COLORREF kTextGreen = RGB(0, 168, 132);
constexpr COLORREF kAccentTeal = RGB(0, 168, 132);
constexpr COLORREF kBtnPrimary = RGB(0, 128, 105);
constexpr COLORREF kBtnHover = RGB(6, 148, 125);
constexpr COLORREF kBorder = RGB(48, 66, 76);
constexpr COLORREF kHeaderBg = RGB(30, 44, 52);
constexpr COLORREF kStatusOnline = RGB(76, 175, 80);
constexpr COLORREF kStatusOffline = RGB(134, 150, 160);
constexpr COLORREF kSentColor = RGB(83, 189, 235);
constexpr COLORREF kFailColor = RGB(244, 91, 91);
constexpr COLORREF kWarning = RGB(245, 191, 65);

constexpr int kSidebarWidth = 340;
constexpr int kHeaderHeight = 64;
constexpr int kKeyPanelHeight = 200;
constexpr int kInputHeight = 56;
constexpr int kMinWidth = 1000;
constexpr int kMinHeight = 700;

// GDI resources
HFONT g_title_font{};
HFONT g_heading_font{};
HFONT g_body_font{};
HFONT g_small_font{};
HFONT g_mono_font{};
HFONT g_btn_font{};
HBRUSH g_bg_brush{};
HBRUSH g_sidebar_brush{};
HBRUSH g_chat_brush{};
HBRUSH g_card_brush{};
HBRUSH g_field_brush{};
HBRUSH g_bubble_out_brush{};
HPEN g_border_pen{};
HBITMAP g_back_buffer{};
HDC g_back_dc{};
int g_back_width{};
int g_back_height{};

// App state
unique_ptr<sender::LocalStorage> g_storage;
unique_ptr<sender::MachineManager> g_machines;
unique_ptr<sender::MessageStore> g_messages;
string g_selected_machine_id;
uint64_t g_next_sequence{1};
int g_chat_scroll_offset{};
int g_chat_scroll_max{};
bool g_show_key_panel{true};

// Controls
HWND g_search_edit{};
HWND g_machine_listbox{};
HWND g_command_edit{};
HWND g_main_window{};

// Async send state
struct AsyncSendResult {
    string machine_id;
    string message_id;
    sender::SendResult result;
};
AsyncSendResult g_async_result{};
bool g_sending{};

wstring widen(const string& value) {
    if (value.empty()) return {};
    const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                         value.data(), static_cast<int>(value.size()),
                                         nullptr, 0);
    if (size <= 0) return L"[encoding error]";
    wstring output(static_cast<size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                        value.data(), static_cast<int>(value.size()),
                        output.data(), size);
    return output;
}

string narrow(const wstring& value) {
    if (value.empty()) return {};
    const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                                         value.data(), static_cast<int>(value.size()),
                                         nullptr, 0, nullptr, nullptr);
    if (size <= 0) return "";
    string output(static_cast<size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                        value.data(), static_cast<int>(value.size()),
                        output.data(), size, nullptr, nullptr);
    return output;
}

string nowUtc() {
    SYSTEMTIME now{};
    GetSystemTime(&now);
    ostringstream out;
    out << setfill('0')
        << setw(4) << now.wYear << '-'
        << setw(2) << now.wMonth << '-'
        << setw(2) << now.wDay << 'T'
        << setw(2) << now.wHour << ':'
        << setw(2) << now.wMinute << ':'
        << setw(2) << now.wSecond << 'Z';
    return out.str();
}

string clockTime() {
    SYSTEMTIME now{};
    GetLocalTime(&now);
    ostringstream out;
    out << setfill('0')
        << setw(2) << now.wHour << ':'
        << setw(2) << now.wMinute << ':'
        << setw(2) << now.wSecond;
    return out.str();
}

string clockTimeUtc() {
    SYSTEMTIME now{};
    GetSystemTime(&now);
    ostringstream out;
    out << setfill('0')
        << setw(2) << now.wHour << ':'
        << setw(2) << now.wMinute << ':'
        << setw(2) << now.wSecond << " UTC";
    return out.str();
}

string statusText(SendStatus s) {
    switch (s) {
        case SendStatus::NotSent: return "Not sent";
        case SendStatus::Sending: return "Sending...";
        case SendStatus::SentToTcp: return "Sent";
        case SendStatus::ConnectionFailed: return "Failed";
    }
    return "Unknown";
}

string generateMsgId() {
    unsigned char bytes[6];
    RAND_bytes(bytes, sizeof(bytes));
    ostringstream id;
    id << hex << setfill('0');
    for (auto b : bytes) id << setw(2) << static_cast<unsigned>(b);
    return "msg_" + id.str();
}

string getStoragePath() {
    char path[MAX_PATH]{};
    GetModuleFileNameA(nullptr, path, MAX_PATH);
    string exe_dir(path);
    auto last_sep = exe_dir.find_last_of("\\/");
    if (last_sep != string::npos) exe_dir = exe_dir.substr(0, last_sep);
    return exe_dir + "\\sender_data";
}

void refreshMachineList() {
    if (!g_machine_listbox) return;
    SendMessageW(g_machine_listbox, LB_RESETCONTENT, 0, 0);
    for (const auto& m : g_machines->machines()) {
        wstring display = widen(m.display_name);
        SendMessageW(g_machine_listbox, LB_ADDSTRING, 0,
                     reinterpret_cast<LPARAM>(display.c_str()));
    }
    // Reselect
    if (!g_selected_machine_id.empty()) {
        const auto& all = g_machines->machines();
        for (size_t i = 0; i < all.size(); ++i) {
            if (all[i].id == g_selected_machine_id) {
                SendMessageW(g_machine_listbox, LB_SETCURSEL, i, 0);
                break;
            }
        }
    }
}

void selectMachine(int index) {
    const auto& all = g_machines->machines();
    if (index >= 0 && index < static_cast<int>(all.size())) {
        g_selected_machine_id = all[index].id;
        g_chat_scroll_offset = 0;
    } else {
        g_selected_machine_id.clear();
    }
}

// ---- DRAWING ----

void destroyBackBuffer() {
    if (g_back_dc) { DeleteDC(g_back_dc); g_back_dc = nullptr; }
    if (g_back_buffer) { DeleteObject(g_back_buffer); g_back_buffer = nullptr; }
    g_back_width = 0;
    g_back_height = 0;
}

bool ensureBackBuffer(HDC dc, int w, int h) {
    if (w <= 0 || h <= 0) return false;
    if (g_back_dc && g_back_buffer && g_back_width == w && g_back_height == h)
        return true;
    destroyBackBuffer();
    g_back_dc = CreateCompatibleDC(dc);
    if (!g_back_dc) return false;
    g_back_buffer = CreateCompatibleBitmap(dc, w, h);
    if (!g_back_buffer) { destroyBackBuffer(); return false; }
    SelectObject(g_back_dc, g_back_buffer);
    g_back_width = w;
    g_back_height = h;
    return true;
}

void drawText(HDC dc, int x, int y, const wstring& text, COLORREF color, HFONT font) {
    SetTextColor(dc, color);
    SetBkMode(dc, TRANSPARENT);
    SelectObject(dc, font);
    TextOutW(dc, x, y, text.c_str(), static_cast<int>(text.size()));
}

void fillRect(HDC dc, int x, int y, int w, int h, COLORREF color) {
    RECT r{x, y, x + w, y + h};
    HBRUSH br = CreateSolidBrush(color);
    FillRect(dc, &r, br);
    DeleteObject(br);
}

void drawRoundRect(HDC dc, int x, int y, int w, int h, COLORREF fill, int radius = 8) {
    HBRUSH br = CreateSolidBrush(fill);
    HPEN pen = CreatePen(PS_SOLID, 1, fill);
    SelectObject(dc, br);
    SelectObject(dc, pen);
    RoundRect(dc, x, y, x + w, y + h, radius, radius);
    DeleteObject(br);
    DeleteObject(pen);
}

void drawSidebar(HDC dc, int width, int height) {
    RECT sidebar{0, 0, kSidebarWidth, height};
    FillRect(dc, &sidebar, g_sidebar_brush);

    // Header bar
    fillRect(dc, 0, 0, kSidebarWidth, kHeaderHeight, kHeaderBg);
    drawText(dc, 16, 10, L"HYBRID PKI", kAccentTeal, g_title_font);
    drawText(dc, 16, 36, L"SCADA Sender", kTextMuted, g_small_font);

    // Separator
    HPEN sepPen = CreatePen(PS_SOLID, 1, kBorder);
    SelectObject(dc, sepPen);
    MoveToEx(dc, kSidebarWidth - 1, 0, nullptr);
    LineTo(dc, kSidebarWidth - 1, height);
    DeleteObject(sepPen);
}

void drawChatHeader(HDC dc, int left, int width) {
    fillRect(dc, left, 0, width, kHeaderHeight, kHeaderBg);

    if (g_selected_machine_id.empty()) {
        drawText(dc, left + 20, 20, L"Select a machine to start messaging",
                 kTextMuted, g_heading_font);
        return;
    }

    const auto* m = g_machines->findMachine(g_selected_machine_id);
    if (!m) return;

    drawText(dc, left + 20, 8, widen(m->display_name), kTextBright, g_heading_font);
    drawText(dc, left + 20, 30,
             widen(m->hostname + ":" + to_string(m->port)),
             kTextMuted, g_small_font);

    // Live clock
    wstring clockStr = widen("UTC " + clockTimeUtc() + "  |  Local " + clockTime());
    SIZE sz{};
    SelectObject(dc, g_mono_font);
    GetTextExtentPoint32W(dc, clockStr.c_str(), static_cast<int>(clockStr.size()), &sz);
    drawText(dc, left + width - sz.cx - 16, 22, clockStr, kTextMuted, g_mono_font);

    // Separator
    HPEN sep = CreatePen(PS_SOLID, 1, kBorder);
    SelectObject(dc, sep);
    MoveToEx(dc, left, kHeaderHeight - 1, nullptr);
    LineTo(dc, left + width, kHeaderHeight - 1);
    DeleteObject(sep);
}

void drawKeyPanel(HDC dc, int left, int top, int width) {
    if (g_selected_machine_id.empty() || !g_show_key_panel) return;

    fillRect(dc, left, top, width, kKeyPanelHeight, kBgCard);

    auto& keys = g_machines->keysFor(g_selected_machine_id);
    int y = top + 10;
    int x = left + 16;
    int col2 = left + width / 2 + 8;

    // RSA section
    drawText(dc, x, y, L"RSA-4096  |  RSA-PSS / SHA-256", kAccentTeal, g_btn_font);
    y += 20;
    if (keys.rsa && keys.rsa->has_private_key()) {
        drawText(dc, x, y, L"\x2713 Key pair available", kStatusOnline, g_body_font);
        y += 18;
        wstring fp = widen("FP: " + keys.rsa->public_fingerprint);
        drawText(dc, x, y, fp, kTextMuted, g_mono_font);
    } else {
        drawText(dc, x, y, L"\x2717 No key pair generated", kTextMuted, g_body_font);
    }

    // GGH section
    y = top + 10;
    drawText(dc, col2, y, L"GGH n=16  |  Educational reference", kAccentTeal, g_btn_font);
    y += 20;
    if (keys.ggh && keys.ggh->has_private_key()) {
        drawText(dc, col2, y, L"\x2713 Key pair available", kStatusOnline, g_body_font);
        y += 18;
        wstring fp = widen("FP: " + keys.ggh->public_fingerprint);
        drawText(dc, col2, y, fp, kTextMuted, g_mono_font);
    } else {
        drawText(dc, col2, y, L"\x2717 No key pair generated", kTextMuted, g_body_font);
    }

    // Separator
    HPEN sep = CreatePen(PS_SOLID, 1, kBorder);
    SelectObject(dc, sep);
    MoveToEx(dc, left, top + kKeyPanelHeight - 1, nullptr);
    LineTo(dc, left + width, top + kKeyPanelHeight - 1);
    DeleteObject(sep);
}

int drawMessageBubbles(HDC dc, int left, int top, int width, int maxHeight) {
    if (g_selected_machine_id.empty()) return 0;

    const auto& msgs = g_messages->messagesFor(g_selected_machine_id);
    if (msgs.empty()) {
        drawText(dc, left + width / 2 - 100, top + maxHeight / 2,
                 L"No messages yet. Send a command!",
                 kTextMuted, g_body_font);
        return 0;
    }

    // Calculate total content height
    const int bubblePad = 10;
    const int lineH = 16;
    const int bubbleGap = 8;
    int totalHeight = 0;

    struct BubbleInfo {
        int height;
        const MessageRecord* msg;
    };
    vector<BubbleInfo> bubbles;

    for (const auto& msg : msgs) {
        int h = bubblePad * 2 + lineH * 4; // cmd + timestamp + seq + status
        totalHeight += h + bubbleGap;
        bubbles.push_back({h, &msg});
    }

    g_chat_scroll_max = max(0, totalHeight - maxHeight);
    g_chat_scroll_offset = max(0, min(g_chat_scroll_offset, g_chat_scroll_max));

    // Draw visible bubbles
    int y = top - g_chat_scroll_offset;
    int bubbleWidth = min(width - 40, 500);

    HRGN clipRgn = CreateRectRgn(left, top, left + width, top + maxHeight);
    SelectClipRgn(dc, clipRgn);

    for (const auto& bi : bubbles) {
        const auto* msg = bi.msg;
        int bx = msg->is_outgoing ? (left + width - bubbleWidth - 16) : (left + 16);

        if (y + bi.height > top && y < top + maxHeight) {
            COLORREF bubbleColor = msg->is_outgoing ? kBgBubbleOut : kBgBubbleIn;
            drawRoundRect(dc, bx, y, bubbleWidth, bi.height, bubbleColor, 12);

            int tx = bx + bubblePad;
            int ty = y + bubblePad;

            // Command text
            wstring cmdText = widen(msg->command);
            drawText(dc, tx, ty, cmdText, kTextBright, g_body_font);
            ty += lineH;

            // Timestamp
            wstring tsText = widen("UTC: " + msg->timestamp_utc);
            drawText(dc, tx, ty, tsText, kTextMuted, g_small_font);
            ty += lineH;

            // Sequence
            wstring seqText = widen("Seq #" + to_string(msg->sequence));
            drawText(dc, tx, ty, seqText, kTextMuted, g_small_font);
            ty += lineH;

            // Status
            COLORREF statusColor = kTextMuted;
            if (msg->status == SendStatus::SentToTcp) statusColor = kSentColor;
            else if (msg->status == SendStatus::ConnectionFailed) statusColor = kFailColor;
            else if (msg->status == SendStatus::Sending) statusColor = kWarning;
            wstring stText = widen(statusText(msg->status));
            if (msg->rsa_signature_size > 0) {
                stText += widen("  |  RSA:" + to_string(msg->rsa_signature_size) + "B");
            }
            if (msg->ggh_signature_size > 0) {
                stText += widen("  GGH:" + to_string(msg->ggh_signature_size) + "B");
            }
            drawText(dc, tx, ty, stText, statusColor, g_small_font);
        }
        y += bi.height + bubbleGap;
    }

    SelectClipRgn(dc, nullptr);
    DeleteObject(clipRgn);

    return totalHeight;
}

void drawInputArea(HDC dc, int left, int bottom, int width) {
    fillRect(dc, left, bottom - kInputHeight, width, kInputHeight, kHeaderBg);

    HPEN sep = CreatePen(PS_SOLID, 1, kBorder);
    SelectObject(dc, sep);
    MoveToEx(dc, left, bottom - kInputHeight, nullptr);
    LineTo(dc, left + width, bottom - kInputHeight);
    DeleteObject(sep);
}

void paintWindow(HDC dc, int width, int height) {
    RECT full{0, 0, width, height};
    FillRect(dc, &full, g_chat_brush);

    drawSidebar(dc, width, height);

    int chatLeft = kSidebarWidth;
    int chatWidth = width - kSidebarWidth;

    drawChatHeader(dc, chatLeft, chatWidth);

    if (!g_selected_machine_id.empty()) {
        int contentTop = kHeaderHeight;
        drawKeyPanel(dc, chatLeft, contentTop, chatWidth);
        int msgTop = contentTop + (g_show_key_panel ? kKeyPanelHeight : 0);
        int msgHeight = height - msgTop - kInputHeight;
        drawMessageBubbles(dc, chatLeft, msgTop, chatWidth, msgHeight);
        drawInputArea(dc, chatLeft, height, chatWidth);
    }
}

void createFonts() {
    g_title_font = CreateFontW(22, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
    g_heading_font = CreateFontW(16, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
    g_body_font = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
    g_small_font = CreateFontW(12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
    g_mono_font = CreateFontW(12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, FIXED_PITCH, L"Cascadia Mono");
    g_btn_font = CreateFontW(13, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");

    g_bg_brush = CreateSolidBrush(kBgDeep);
    g_sidebar_brush = CreateSolidBrush(kBgSidebar);
    g_chat_brush = CreateSolidBrush(kBgChat);
    g_card_brush = CreateSolidBrush(kBgCard);
    g_field_brush = CreateSolidBrush(kBgField);
    g_bubble_out_brush = CreateSolidBrush(kBgBubbleOut);
    g_border_pen = CreatePen(PS_SOLID, 1, kBorder);
}

void destroyFonts() {
    HGDIOBJ objs[] = {g_title_font, g_heading_font, g_body_font, g_small_font,
                      g_mono_font, g_btn_font, g_bg_brush, g_sidebar_brush,
                      g_chat_brush, g_card_brush, g_field_brush, g_bubble_out_brush,
                      g_border_pen};
    for (auto o : objs) if (o) DeleteObject(o);
}

HWND makeCtrl(const wchar_t* cls, const wchar_t* text, DWORD style, int id,
              HWND parent, HFONT font, DWORD exStyle = 0) {
    HWND h = CreateWindowExW(exStyle, cls, text, style, 0, 0, 0, 0, parent,
                              reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
                              GetModuleHandleW(nullptr), nullptr);
    if (h) SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    return h;
}

HWND makeButton(const wchar_t* text, int id, HWND parent) {
    return makeCtrl(L"BUTTON", text,
                    WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                    id, parent, g_btn_font);
}

void layoutControls(HWND window) {
    RECT client{};
    GetClientRect(window, &client);
    int w = client.right;
    int h = client.bottom;

    // Search edit
    if (g_search_edit)
        SetWindowPos(g_search_edit, nullptr, 8, kHeaderHeight + 8,
                     kSidebarWidth - 16, 28, SWP_NOZORDER);

    // Sidebar buttons
    int btnY = kHeaderHeight + 44;
    int btnW = (kSidebarWidth - 32) / 3;
    HWND addBtn = GetDlgItem(window, kAddMachine);
    HWND editBtn = GetDlgItem(window, kEditMachine);
    HWND delBtn = GetDlgItem(window, kDeleteMachine);
    if (addBtn)
        SetWindowPos(addBtn, nullptr, 8, btnY, btnW, 28, SWP_NOZORDER);
    if (editBtn)
        SetWindowPos(editBtn, nullptr, 8 + btnW + 4, btnY, btnW, 28, SWP_NOZORDER);
    if (delBtn)
        SetWindowPos(delBtn, nullptr, 8 + (btnW + 4) * 2, btnY, btnW, 28, SWP_NOZORDER);

    // Machine list
    if (g_machine_listbox)
        SetWindowPos(g_machine_listbox, nullptr, 8, btnY + 36,
                     kSidebarWidth - 16, h - btnY - 44, SWP_NOZORDER);

    // Key gen buttons
    int chatLeft = kSidebarWidth;
    int chatW = w - kSidebarWidth;
    int keyBtnY = kHeaderHeight + kKeyPanelHeight - 36;
    int keyBtnW = (chatW / 2) - 24;
    HWND rsaBtn = GetDlgItem(window, kGenRsa);
    HWND gghBtn = GetDlgItem(window, kGenGgh);
    if (rsaBtn)
        SetWindowPos(rsaBtn, nullptr, chatLeft + 16, keyBtnY,
                     keyBtnW, 28, SWP_NOZORDER);
    if (gghBtn)
        SetWindowPos(gghBtn, nullptr, chatLeft + chatW / 2 + 8, keyBtnY,
                     keyBtnW, 28, SWP_NOZORDER);

    // Show/hide key-related buttons based on selection
    bool hasSel = !g_selected_machine_id.empty();
    if (rsaBtn) ShowWindow(rsaBtn, hasSel && g_show_key_panel ? SW_SHOW : SW_HIDE);
    if (gghBtn) ShowWindow(gghBtn, hasSel && g_show_key_panel ? SW_SHOW : SW_HIDE);

    // Command input and send button
    int inputY = h - kInputHeight + 10;
    int cmdW = chatW - 160;
    if (g_command_edit) {
        SetWindowPos(g_command_edit, nullptr, chatLeft + 12, inputY,
                     cmdW, 32, SWP_NOZORDER);
        ShowWindow(g_command_edit, hasSel ? SW_SHOW : SW_HIDE);
    }
    HWND sendBtn = GetDlgItem(window, kSendCommand);
    if (sendBtn) {
        SetWindowPos(sendBtn, nullptr, chatLeft + cmdW + 20, inputY,
                     120, 32, SWP_NOZORDER);
        ShowWindow(sendBtn, hasSel ? SW_SHOW : SW_HIDE);
    }
}

// ---- DIALOG HELPERS ----

struct MachineDialogData {
    wchar_t name[128]{};
    wchar_t hostname[256]{};
    wchar_t port[8]{};
    bool is_edit{};
};

INT_PTR CALLBACK machineDialogProc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_INITDIALOG: {
            auto* data = reinterpret_cast<MachineDialogData*>(lp);
            SetWindowLongPtrW(dlg, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(data));
            SetDlgItemTextW(dlg, 1001, data->name);
            SetDlgItemTextW(dlg, 1002, data->hostname);
            SetDlgItemTextW(dlg, 1003, data->port);
            SetWindowTextW(dlg, data->is_edit ? L"Edit Machine" : L"Add Machine");
            return TRUE;
        }
        case WM_COMMAND:
            if (LOWORD(wp) == IDOK) {
                auto* data = reinterpret_cast<MachineDialogData*>(
                    GetWindowLongPtrW(dlg, GWLP_USERDATA));
                GetDlgItemTextW(dlg, 1001, data->name, 128);
                GetDlgItemTextW(dlg, 1002, data->hostname, 256);
                GetDlgItemTextW(dlg, 1003, data->port, 8);
                EndDialog(dlg, IDOK);
                return TRUE;
            }
            if (LOWORD(wp) == IDCANCEL) {
                EndDialog(dlg, IDCANCEL);
                return TRUE;
            }
            break;
        case WM_CLOSE:
            EndDialog(dlg, IDCANCEL);
            return TRUE;
    }
    return FALSE;
}

HWND createMachineDialog(HWND parent, MachineDialogData* data) {
    // Build dialog template in memory
    alignas(4) char buf[1024]{};
    auto* dlgTemplate = reinterpret_cast<DLGTEMPLATE*>(buf);
    dlgTemplate->style = DS_MODALFRAME | WS_POPUP | WS_CAPTION | WS_SYSMENU | DS_CENTER;
    dlgTemplate->dwExtendedStyle = 0;
    dlgTemplate->cdit = 8; // controls
    dlgTemplate->x = 0; dlgTemplate->y = 0;
    dlgTemplate->cx = 200; dlgTemplate->cy = 130;

    auto* p = reinterpret_cast<WORD*>(dlgTemplate + 1);
    *p++ = 0; // menu
    *p++ = 0; // class
    // title
    const wchar_t* title = L"Machine";
    while (*title) *p++ = *title++;
    *p++ = 0;

    auto addItem = [&](DWORD style, WORD x, WORD y, WORD cx, WORD cy, WORD id,
                        const wchar_t* cls, const wchar_t* text) {
        p = reinterpret_cast<WORD*>(
            (reinterpret_cast<uintptr_t>(p) + 3) & ~uintptr_t(3));
        auto* item = reinterpret_cast<DLGITEMTEMPLATE*>(p);
        item->style = style | WS_VISIBLE | WS_CHILD;
        item->dwExtendedStyle = 0;
        item->x = x; item->y = y; item->cx = cx; item->cy = cy;
        item->id = id;
        p = reinterpret_cast<WORD*>(item + 1);
        while (*cls) *p++ = *cls++;
        *p++ = 0;
        while (*text) *p++ = *text++;
        *p++ = 0;
        *p++ = 0; // extra
    };

    addItem(SS_LEFT, 8, 8, 60, 10, 0xFFFF, L"STATIC", L"Name:");
    addItem(ES_AUTOHSCROLL | WS_BORDER | WS_TABSTOP, 70, 6, 120, 14, 1001,
            L"EDIT", L"");
    addItem(SS_LEFT, 8, 28, 60, 10, 0xFFFF, L"STATIC", L"Host/IP:");
    addItem(ES_AUTOHSCROLL | WS_BORDER | WS_TABSTOP, 70, 26, 120, 14, 1002,
            L"EDIT", L"");
    addItem(SS_LEFT, 8, 48, 60, 10, 0xFFFF, L"STATIC", L"Port:");
    addItem(ES_AUTOHSCROLL | WS_BORDER | WS_TABSTOP, 70, 46, 60, 14, 1003,
            L"EDIT", L"");
    addItem(BS_DEFPUSHBUTTON | WS_TABSTOP, 40, 72, 50, 14, IDOK,
            L"BUTTON", L"OK");
    addItem(BS_PUSHBUTTON | WS_TABSTOP, 100, 72, 50, 14, IDCANCEL,
            L"BUTTON", L"Cancel");

    DialogBoxIndirectParamW(GetModuleHandleW(nullptr),
                            dlgTemplate, parent, machineDialogProc,
                            reinterpret_cast<LPARAM>(data));
    return nullptr;
}

void handleAddMachine(HWND window) {
    MachineDialogData data{};
    wcscpy(data.port, L"502");
    data.is_edit = false;
    createMachineDialog(window, &data);
    if (wcslen(data.name) == 0) return;

    string name = narrow(data.name);
    string host = narrow(data.hostname);
    int port = _wtoi(data.port);
    if (port <= 0 || port > 65535) port = 502;
    if (name.empty()) name = "Machine";
    if (host.empty()) host = "127.0.0.1";

    g_selected_machine_id = g_machines->addMachine(name, host,
                                                    static_cast<uint16_t>(port));
    refreshMachineList();
    InvalidateRect(window, nullptr, FALSE);
}

void handleEditMachine(HWND window) {
    if (g_selected_machine_id.empty()) return;
    auto* m = g_machines->findMachine(g_selected_machine_id);
    if (!m) return;

    MachineDialogData data{};
    data.is_edit = true;
    wcsncpy(data.name, widen(m->display_name).c_str(), 127);
    wcsncpy(data.hostname, widen(m->hostname).c_str(), 255);
    wcsncpy(data.port, widen(to_string(m->port)).c_str(), 7);
    createMachineDialog(window, &data);

    string name = narrow(data.name);
    string host = narrow(data.hostname);
    int port = _wtoi(data.port);
    if (port <= 0 || port > 65535) port = 502;
    if (!name.empty()) {
        g_machines->updateMachine(g_selected_machine_id, name, host,
                                  static_cast<uint16_t>(port));
        refreshMachineList();
        InvalidateRect(window, nullptr, FALSE);
    }
}

void handleDeleteMachine(HWND window) {
    if (g_selected_machine_id.empty()) return;
    auto* m = g_machines->findMachine(g_selected_machine_id);
    if (!m) return;

    wstring msg = L"Delete machine \"" + widen(m->display_name) +
                  L"\"?\n\nMessage history will be preserved on disk.";
    int result = MessageBoxW(window, msg.c_str(), L"Confirm Delete",
                             MB_YESNO | MB_ICONQUESTION);
    if (result != IDYES) return;

    g_machines->removeMachine(g_selected_machine_id);
    g_selected_machine_id.clear();
    refreshMachineList();
    InvalidateRect(window, nullptr, FALSE);
}

void handleGenerateRsa(HWND window) {
    if (g_selected_machine_id.empty()) return;
    try {
        auto& keys = g_machines->keysFor(g_selected_machine_id);
        keys.rsa = make_unique<hybrid_pki::RSAKeyPair>(
            hybrid_pki::generateRSAKeyPair());
        InvalidateRect(window, nullptr, FALSE);
    } catch (const exception& e) {
        MessageBoxW(window, widen(e.what()).c_str(), L"RSA Key Generation", MB_OK | MB_ICONERROR);
    }
}

void handleGenerateGgh(HWND window) {
    if (g_selected_machine_id.empty()) return;
    try {
        auto& keys = g_machines->keysFor(g_selected_machine_id);
        keys.ggh = make_unique<hybrid_pki::GGHKeyPair>(
            hybrid_pki::generateGGHKeyPair());
        InvalidateRect(window, nullptr, FALSE);
    } catch (const exception& e) {
        MessageBoxW(window, widen(e.what()).c_str(), L"GGH Key Generation", MB_OK | MB_ICONERROR);
    }
}

void handleSendCommand(HWND window) {
    if (g_selected_machine_id.empty() || g_sending) return;

    auto& keys = g_machines->keysFor(g_selected_machine_id);
    if (!keys.rsa || !keys.ggh) {
        MessageBoxW(window, L"Generate both RSA-4096 and GGH keys before sending.",
                    L"Keys Required", MB_OK | MB_ICONWARNING);
        return;
    }

    wchar_t cmdBuf[512]{};
    GetWindowTextW(g_command_edit, cmdBuf, 512);
    string command = narrow(wstring(cmdBuf));
    if (command.empty()) {
        MessageBoxW(window, L"Enter a command to send.", L"Empty Command", MB_OK);
        return;
    }

    const auto* m = g_machines->findMachine(g_selected_machine_id);
    if (!m) return;

    try {
        // Build envelope
        hybrid_pki::CommandEnvelope envelope{command, nowUtc(), g_next_sequence};

        // Hybrid sign using existing crypto
        auto result = hybrid_pki::hybridSign(envelope, *keys.rsa, *keys.ggh);
        ++g_next_sequence;
        g_storage->saveSequence(g_next_sequence);

        // Create message record
        MessageRecord msg;
        msg.id = generateMsgId();
        msg.machine_id = g_selected_machine_id;
        msg.command = command;
        msg.timestamp_utc = envelope.timestamp_utc;
        msg.sequence = envelope.sequence;
        msg.rsa_fingerprint = keys.rsa->public_fingerprint;
        msg.ggh_fingerprint = keys.ggh->public_fingerprint;
        msg.rsa_signature_size = result.signed_command.rsa_signature.size();
        msg.ggh_signature_size = hybrid_pki::gghSignatureSize(result.signed_command.ggh_signature);
        msg.status = SendStatus::Sending;
        msg.is_outgoing = true;
        g_messages->addMessage(msg);
        g_machines->touchActivity(g_selected_machine_id);

        // Scroll to bottom
        g_chat_scroll_offset = 999999;

        // Clear input
        SetWindowTextW(g_command_edit, L"");
        InvalidateRect(window, nullptr, FALSE);

        // Async TCP send
        g_sending = true;
        string host = m->hostname;
        uint16_t port = m->port;
        string machId = g_selected_machine_id;
        string msgId = msg.id;
        auto frame = sender::frameMessage(
            command, envelope.timestamp_utc, envelope.sequence,
            result.signed_command.rsa_signature,
            result.signed_command.ggh_signature.lattice_point);

        HWND wnd = window;
        thread([=]() {
            sender::TcpClient client;
            sender::SendResult sendRes = sender::SendResult::Failed;
            auto connRes = client.connect(host, port, 3000);
            if (connRes == sender::ConnectResult::Success) {
                sendRes = client.sendFrame(frame);
            }
            g_async_result.machine_id = machId;
            g_async_result.message_id = msgId;
            g_async_result.result = sendRes;
            PostMessageW(wnd, kAsyncSendDone, 0, 0);
        }).detach();

    } catch (const exception& e) {
        MessageBoxW(window, widen(string("Signing failed: ") + e.what()).c_str(),
                    L"Send Error", MB_OK | MB_ICONERROR);
    }
}

LRESULT CALLBACK windowProc(HWND window, UINT message, WPARAM wp, LPARAM lp) {
    switch (message) {
        case WM_CREATE: {
            createFonts();

            // Initialize storage
            g_storage = make_unique<sender::LocalStorage>(getStoragePath());
            g_machines = make_unique<sender::MachineManager>(*g_storage);
            g_messages = make_unique<sender::MessageStore>(*g_storage);
            g_next_sequence = g_storage->loadSequence();
            if (g_next_sequence == 0) g_next_sequence = 1;

            // Search bar
            g_search_edit = makeCtrl(L"EDIT", L"",
                WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | WS_TABSTOP,
                kSearchEdit, window, g_body_font, WS_EX_CLIENTEDGE);
            SetWindowTextW(g_search_edit, L"");
            SendMessageW(g_search_edit, EM_SETCUEBANNER, TRUE,
                         reinterpret_cast<LPARAM>(L"Search machines..."));

            // Sidebar buttons
            makeButton(L"+ ADD", kAddMachine, window);
            makeButton(L"EDIT", kEditMachine, window);
            makeButton(L"DELETE", kDeleteMachine, window);

            // Machine list
            g_machine_listbox = makeCtrl(L"LISTBOX", L"",
                WS_CHILD | WS_VISIBLE | LBS_NOTIFY | WS_VSCROLL | LBS_NOINTEGRALHEIGHT,
                kMachineList, window, g_body_font, WS_EX_CLIENTEDGE);

            // Key gen buttons
            makeButton(L"GENERATE RSA-4096 KEY", kGenRsa, window);
            makeButton(L"GENERATE GGH KEY", kGenGgh, window);

            // Command input
            g_command_edit = makeCtrl(L"EDIT", L"",
                WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | WS_TABSTOP,
                kCommandEdit, window, g_body_font, WS_EX_CLIENTEDGE);
            SendMessageW(g_command_edit, EM_SETCUEBANNER, TRUE,
                         reinterpret_cast<LPARAM>(L"Enter SCADA command..."));

            // Send button
            makeButton(L"SIGN && SEND", kSendCommand, window);

            refreshMachineList();
            layoutControls(window);
            SetTimer(window, kClockTimer, 1000, nullptr);
            return 0;
        }

        case WM_TIMER:
            if (wp == kClockTimer) {
                // Repaint header clock area only
                RECT client{};
                GetClientRect(window, &client);
                RECT clockRect{kSidebarWidth, 0, client.right, kHeaderHeight};
                InvalidateRect(window, &clockRect, FALSE);
            }
            return 0;

        case WM_SIZE:
            layoutControls(window);
            InvalidateRect(window, nullptr, FALSE);
            return 0;

        case WM_COMMAND: {
            if (HIWORD(wp) == BN_CLICKED) {
                switch (LOWORD(wp)) {
                    case kAddMachine: handleAddMachine(window); break;
                    case kEditMachine: handleEditMachine(window); break;
                    case kDeleteMachine: handleDeleteMachine(window); break;
                    case kGenRsa: handleGenerateRsa(window); break;
                    case kGenGgh: handleGenerateGgh(window); break;
                    case kSendCommand: handleSendCommand(window); break;
                }
            }
            if (HIWORD(wp) == LBN_SELCHANGE && LOWORD(wp) == kMachineList) {
                int sel = static_cast<int>(
                    SendMessageW(g_machine_listbox, LB_GETCURSEL, 0, 0));
                selectMachine(sel);
                layoutControls(window);
                InvalidateRect(window, nullptr, FALSE);
            }
            return 0;
        }

        case kAsyncSendDone: {
            g_sending = false;
            SendStatus newStatus = (g_async_result.result == sender::SendResult::Success)
                                   ? SendStatus::SentToTcp
                                   : SendStatus::ConnectionFailed;
            g_messages->updateMessageStatus(g_async_result.machine_id,
                                            g_async_result.message_id,
                                            newStatus);
            InvalidateRect(window, nullptr, FALSE);
            return 0;
        }

        case WM_MOUSEWHEEL: {
            int delta = GET_WHEEL_DELTA_WPARAM(wp);
            g_chat_scroll_offset -= delta / 2;
            g_chat_scroll_offset = max(0, min(g_chat_scroll_offset, g_chat_scroll_max));
            InvalidateRect(window, nullptr, FALSE);
            return 0;
        }

        case WM_DRAWITEM: {
            const auto* draw = reinterpret_cast<const DRAWITEMSTRUCT*>(lp);
            if (!draw || draw->CtlType != ODT_BUTTON) return 0;

            int id = static_cast<int>(draw->CtlID);
            bool primary = (id == kGenRsa || id == kGenGgh || id == kSendCommand ||
                           id == kAddMachine);

            HBRUSH fill = CreateSolidBrush(primary ? kBtnPrimary : kBgCard);
            HPEN border = CreatePen(PS_SOLID, 1, primary ? kAccentTeal : kBorder);
            SelectObject(draw->hDC, fill);
            SelectObject(draw->hDC, border);

            RECT r = draw->rcItem;
            InflateRect(&r, -1, -1);
            RoundRect(draw->hDC, r.left, r.top, r.right, r.bottom, 6, 6);

            SetBkMode(draw->hDC, TRANSPARENT);
            SetTextColor(draw->hDC, primary ? RGB(245, 255, 252) : kTextBright);
            SelectObject(draw->hDC, g_btn_font);

            wchar_t text[128]{};
            GetWindowTextW(draw->hwndItem, text, 128);
            DrawTextW(draw->hDC, text, -1, &r, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

            DeleteObject(fill);
            DeleteObject(border);
            return TRUE;
        }

        case WM_PAINT: {
            PAINTSTRUCT ps{};
            HDC dc = BeginPaint(window, &ps);
            RECT client{};
            GetClientRect(window, &client);

            if (ensureBackBuffer(dc, client.right, client.bottom)) {
                paintWindow(g_back_dc, client.right, client.bottom);
                BitBlt(dc, ps.rcPaint.left, ps.rcPaint.top,
                       ps.rcPaint.right - ps.rcPaint.left,
                       ps.rcPaint.bottom - ps.rcPaint.top,
                       g_back_dc, ps.rcPaint.left, ps.rcPaint.top, SRCCOPY);
            } else {
                paintWindow(dc, client.right, client.bottom);
            }
            EndPaint(window, &ps);
            return 0;
        }

        case WM_CTLCOLORLISTBOX: {
            HDC dc = reinterpret_cast<HDC>(wp);
            SetTextColor(dc, kTextBright);
            SetBkColor(dc, kBgSidebar);
            return reinterpret_cast<LRESULT>(g_sidebar_brush);
        }

        case WM_CTLCOLOREDIT: {
            HDC dc = reinterpret_cast<HDC>(wp);
            SetTextColor(dc, kTextBright);
            SetBkColor(dc, kBgField);
            return reinterpret_cast<LRESULT>(g_field_brush);
        }

        case WM_CTLCOLORSTATIC: {
            HDC dc = reinterpret_cast<HDC>(wp);
            SetBkMode(dc, TRANSPARENT);
            SetTextColor(dc, kTextBright);
            SetBkColor(dc, kBgCard);
            return reinterpret_cast<LRESULT>(g_card_brush);
        }

        case WM_ERASEBKGND:
            return 1;

        case WM_GETMINMAXINFO: {
            auto* info = reinterpret_cast<MINMAXINFO*>(lp);
            info->ptMinTrackSize.x = kMinWidth;
            info->ptMinTrackSize.y = kMinHeight;
            return 0;
        }

        case WM_DESTROY:
            KillTimer(window, kClockTimer);
            destroyBackBuffer();
            destroyFonts();
            PostQuitMessage(0);
            return 0;

        default:
            return DefWindowProcW(window, message, wp, lp);
    }
}

}  // anonymous namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int commandShow) {
    INITCOMMONCONTROLSEX cc{sizeof(cc), ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&cc);

    const wchar_t* className = L"HybridPkiSenderGui";
    WNDCLASSW wc{};
    wc.hInstance = instance;
    wc.lpszClassName = className;
    wc.lpfnWndProc = windowProc;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = nullptr;

    if (!RegisterClassW(&wc) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS)
        return 1;

    g_main_window = CreateWindowExW(
        WS_EX_COMPOSITED, className,
        L"HYBRID PKI - SCADA SENDER",
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT, 1280, 850,
        nullptr, nullptr, instance, nullptr);

    if (!g_main_window) return 1;

    ShowWindow(g_main_window, commandShow);
    UpdateWindow(g_main_window);

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return static_cast<int>(msg.wParam);
}
