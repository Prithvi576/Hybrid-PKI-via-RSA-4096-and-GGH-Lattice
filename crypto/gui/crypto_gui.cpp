#include "crypto_api.hpp"

#include <windows.h>
#include <commctrl.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

using namespace std;

namespace {

constexpr int kRsaGenerate = 101;
constexpr int kGghGenerate = 102;
constexpr int kSign = 103;
constexpr int kVerify = 104;
constexpr int kModifyCommand = 105;
constexpr int kModifyTimestamp = 106;
constexpr int kModifySequence = 107;
constexpr int kCorruptRsa = 108;
constexpr int kCorruptGgh = 109;
constexpr int kRunBenchmark = 110;
constexpr int kResetTamper = 111;
constexpr UINT_PTR kClockTimer = 1;

constexpr COLORREF kBgDeep = RGB(9, 14, 24);
constexpr COLORREF kBgCard = RGB(18, 29, 45);
constexpr COLORREF kBgField = RGB(13, 21, 34);
constexpr COLORREF kBgHeader = RGB(13, 23, 38);
constexpr COLORREF kTextBright = RGB(235, 242, 250);
constexpr COLORREF kTextMuted = RGB(153, 171, 194);
constexpr COLORREF kAccentTeal = RGB(46, 210, 180);
constexpr COLORREF kAccentBlue = RGB(83, 150, 255);
constexpr COLORREF kSuccess = RGB(62, 211, 134);
constexpr COLORREF kFailure = RGB(244, 91, 91);
constexpr COLORREF kWarning = RGB(245, 191, 65);
constexpr COLORREF kBtnFace = RGB(28, 45, 68);
constexpr COLORREF kBorder = RGB(48, 72, 102);

constexpr int kMargin = 18;
constexpr int kGap = 12;
constexpr int kCardPad = 16;
constexpr int kHeaderHeight = 76;
constexpr int kFooterHeight = 76;
constexpr int kMinWidth = 1100;
constexpr int kMinHeight = 820;

struct Controls {
    HWND rsa_status{};
    HWND rsa_fingerprint{};
    HWND ggh_status{};
    HWND ggh_fingerprint{};
    HWND command{};
    HWND timestamp{};
    HWND sequence{};
    HWND verification{};
    HWND signature_info{};
    HWND details{};
    HWND benchmarks{};
    HWND event_log{};
};

struct Timings {
    optional<chrono::nanoseconds> rsa_keygen;
    optional<chrono::nanoseconds> ggh_keygen;
    optional<hybrid_pki::OperationMeasurements> sign;
    optional<hybrid_pki::OperationMeasurements> verify;
};

struct AppState {
    unique_ptr<hybrid_pki::RSAKeyPair> rsa;
    unique_ptr<hybrid_pki::GGHKeyPair> ggh;
    hybrid_pki::HybridSignedCommand signed_command;
    hybrid_pki::HybridSignedCommand original_signed_command;
    bool has_signed_command{};
    bool tampered{};
    uint64_t next_sequence{1};
    Timings timings;
};

struct Layout {
    RECT keys{};
    RECT signature{};
    RECT details{};
    RECT command{};
    RECT verification{};
    RECT benchmarks{};
    RECT log{};
    RECT tamper{};
};

Controls g_controls;
AppState g_state;

HFONT g_title_font{};
HFONT g_heading_font{};
HFONT g_body_font{};
HFONT g_mono_font{};
HFONT g_label_font{};
HFONT g_btn_font{};

HBRUSH g_bg_brush{};
HBRUSH g_card_brush{};
HBRUSH g_field_brush{};
HBRUSH g_btn_brush{};
HPEN g_border_pen{};
HPEN g_accent_pen{};
HBITMAP g_back_buffer{};
HDC g_back_dc{};
int g_back_width{};
int g_back_height{};

bool isPrimaryButton(const int id) {
    return id == kRsaGenerate || id == kGghGenerate || id == kSign ||
           id == kVerify || id == kRunBenchmark || id == kResetTamper;
}

wstring widen(const string& value) {
    if (value.empty()) return {};

    const int size = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), nullptr, 0);

    if (size <= 0) return L"[encoding error]";

    wstring output(static_cast<size_t>(size), L'\0');
    MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), output.data(), size);

    return output;
}

string narrow(const wstring& value) {
    if (value.empty()) return {};

    const int size = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);

    if (size <= 0) throw invalid_argument("command must be valid UTF-8");

    string output(static_cast<size_t>(size), '\0');
    WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), output.data(), size, nullptr, nullptr);

    return output;
}

void setText(HWND control, const string& value) {
    if (!control) return;

    const wstring text = widen(value);
    SetWindowTextW(control, text.c_str());

    // Static controls use transparent backgrounds. Invalidate the control
    // after changing text so old glyphs cannot remain visible.
    InvalidateRect(control, nullptr, TRUE);
    UpdateWindow(control);
}

wstring controlText(HWND control) {
    if (!control) return {};

    const int length = GetWindowTextLengthW(control);
    if (length <= 0) return {};

    vector<wchar_t> buffer(static_cast<size_t>(length) + 1);
    GetWindowTextW(control, buffer.data(), length + 1);
    return wstring(buffer.data(), static_cast<size_t>(length));
}

string nowUtc() {
    SYSTEMTIME now{};
    GetSystemTime(&now);

    ostringstream output;
    output << setfill('0')
           << setw(4) << now.wYear << '-'
           << setw(2) << now.wMonth << '-'
           << setw(2) << now.wDay << 'T'
           << setw(2) << now.wHour << ':'
           << setw(2) << now.wMinute << ':'
           << setw(2) << now.wSecond << 'Z';

    return output.str();
}

string clockTime() {
    SYSTEMTIME now{};
    GetLocalTime(&now);

    ostringstream output;
    output << setfill('0')
           << setw(2) << now.wHour << ':'
           << setw(2) << now.wMinute << ':'
           << setw(2) << now.wSecond;

    return output.str();
}

string durationText(const chrono::nanoseconds duration) {
    const auto microseconds =
        chrono::duration_cast<chrono::microseconds>(duration).count();

    ostringstream output;

    if (microseconds >= 1000) {
        output << fixed << setprecision(2)
               << static_cast<double>(microseconds) / 1000.0 << " ms";
    } else {
        output << microseconds << " us";
    }

    return output.str();
}

void appendLog(const string& line) {
    if (!g_controls.event_log) return;

    const string message = "[" + clockTime() + "]  " + line + "\r\n";
    const wstring entry = widen(message);
    const int end = GetWindowTextLengthW(g_controls.event_log);

    SendMessageW(g_controls.event_log, EM_SETSEL, end, end);
    SendMessageW(
        g_controls.event_log, EM_REPLACESEL, FALSE,
        reinterpret_cast<LPARAM>(entry.c_str()));
    SendMessageW(g_controls.event_log, EM_SCROLLCARET, 0, 0);
}

void showError(HWND window, const string& message) {
    MessageBoxW(
        window, widen(message).c_str(),
        L"Cryptographic Operation",
        MB_OK | MB_ICONERROR);
}

void resetVerification() {
    setText(
        g_controls.verification,
        "  RSA verification:     PENDING\r\n"
        "  GGH verification:     PENDING\r\n"
        "  Hybrid result:        PENDING");
}

void updateDetails() {
    ostringstream details;

    details << "GGH Configuration\r\n  "
            << hybrid_pki::gghConfiguration()
            << "\r\n\r\nSecurity\r\n"
            << "  Private key material is never rendered or logged."
            << "\r\n\r\nCanonical Message\r\n";

    if (g_state.has_signed_command) {
        const auto canonical =
            hybrid_pki::canonicalize(g_state.signed_command.envelope);

        details << "  " << canonical.size()
                << " bytes, deterministic UTF-8 fields\r\n"
                << "  COMMAND=" << g_state.signed_command.envelope.command << "\r\n"
                << "  TIMESTAMP=" << g_state.signed_command.envelope.timestamp_utc << "\r\n"
                << "  SEQUENCE=" << g_state.signed_command.envelope.sequence;

        if (g_state.tampered) {
            details << "\r\n  STATUS=TAMPERED PAYLOAD";
        }
    } else {
        details << "  Generated when you click SIGN COMMAND.";
    }

    setText(g_controls.details, details.str());
}

void updateBenchmarks() {
    const auto one = [](const optional<chrono::nanoseconds>& duration) {
        return duration ? durationText(*duration) : string("--");
    };

    const auto part =
        [](const optional<hybrid_pki::OperationMeasurements>& metrics,
           const chrono::nanoseconds hybrid_pki::OperationMeasurements::*member) {
            return metrics ? durationText((*metrics).*member) : string("--");
        };

    ostringstream benchmark;

    benchmark << "  RSA-4096 keygen:       "
              << one(g_state.timings.rsa_keygen) << "\r\n"
              << "  GGH keygen:            "
              << one(g_state.timings.ggh_keygen) << "\r\n"
              << "  RSA signing:           "
              << part(g_state.timings.sign, &hybrid_pki::OperationMeasurements::rsa) << "\r\n"
              << "  GGH signing:           "
              << part(g_state.timings.sign, &hybrid_pki::OperationMeasurements::ggh) << "\r\n"
              << "  Hybrid signing:        "
              << part(g_state.timings.sign, &hybrid_pki::OperationMeasurements::hybrid) << "\r\n"
              << "  RSA verification:      "
              << part(g_state.timings.verify, &hybrid_pki::OperationMeasurements::rsa) << "\r\n"
              << "  GGH verification:      "
              << part(g_state.timings.verify, &hybrid_pki::OperationMeasurements::ggh) << "\r\n"
              << "  Hybrid verification:   "
              << part(g_state.timings.verify, &hybrid_pki::OperationMeasurements::hybrid);

    if (g_state.has_signed_command) {
        const auto rsa_size = g_state.signed_command.rsa_signature.size();
        const auto ggh_size =
            hybrid_pki::gghSignatureSize(g_state.signed_command.ggh_signature);

        benchmark << "\r\n\r\n"
                  << "  RSA signature size:    " << rsa_size << " bytes\r\n"
                  << "  GGH signature size:    " << ggh_size << " bytes\r\n"
                  << "  Hybrid payload size:   "
                  << rsa_size + ggh_size << " bytes";
    }

    setText(g_controls.benchmarks, benchmark.str());
}

void updateSignatureInfo() {
    if (!g_state.has_signed_command) {
        setText(
            g_controls.signature_info,
            "  No hybrid command has been signed yet.\r\n"
            "  Generate both keys and sign a command to view signature data.");
        return;
    }

    const auto rsa_size = g_state.signed_command.rsa_signature.size();
    const auto ggh_size =
        hybrid_pki::gghSignatureSize(g_state.signed_command.ggh_signature);

    ostringstream info;

    info << "  RSA-4096 signature:   " << rsa_size << " bytes\r\n"
         << "  GGH lattice sig:      " << ggh_size << " bytes\r\n"
         << "  Hybrid total:         " << rsa_size + ggh_size << " bytes";

    if (g_state.rsa) {
        info << "\r\n  RSA fingerprint:      "
             << g_state.rsa->public_fingerprint.substr(
                    0, min<size_t>(16, g_state.rsa->public_fingerprint.size()))
             << "...";
    }

    if (g_state.ggh) {
        info << "\r\n  GGH fingerprint:      "
             << g_state.ggh->public_fingerprint.substr(
                    0, min<size_t>(16, g_state.ggh->public_fingerprint.size()))
             << "...";
    }

    if (g_state.tampered) {
        info << "\r\n  Payload status:       TAMPERED";
    }

    setText(g_controls.signature_info, info.str());
}

bool requireSigned(HWND window) {
    if (g_state.has_signed_command) return true;

    showError(window, "Sign a command before using tampering or verification controls.");
    return false;
}

void generateRsa(HWND window) {
    try {
        appendLog("RSA-4096 key generation started.");

        const auto start = chrono::steady_clock::now();
        auto key =
            make_unique<hybrid_pki::RSAKeyPair>(
                hybrid_pki::generateRSAKeyPair());

        g_state.timings.rsa_keygen =
            chrono::duration_cast<chrono::nanoseconds>(
                chrono::steady_clock::now() - start);

        g_state.rsa = move(key);
        g_state.has_signed_command = false;
        g_state.tampered = false;

        setText(g_controls.rsa_status, "  RSA-4096:  GENERATED  |  RSA-PSS / SHA-256");
        setText(
            g_controls.rsa_fingerprint,
            "  Fingerprint: " + g_state.rsa->public_fingerprint);

        appendLog(
            "RSA-4096 key generated in " +
            durationText(*g_state.timings.rsa_keygen));

        updateBenchmarks();
    } catch (const exception& error) {
        appendLog(string("RSA key generation failed: ") + error.what());
        showError(window, error.what());
    }
}

void generateGgh(HWND window) {
    try {
        appendLog("GGH lattice key generation started.");

        const auto start = chrono::steady_clock::now();
        auto key =
            make_unique<hybrid_pki::GGHKeyPair>(
                hybrid_pki::generateGGHKeyPair());

        g_state.timings.ggh_keygen =
            chrono::duration_cast<chrono::nanoseconds>(
                chrono::steady_clock::now() - start);

        g_state.ggh = move(key);
        g_state.has_signed_command = false;
        g_state.tampered = false;

        setText(
            g_controls.ggh_status,
            "  GGH n=16:  GENERATED  |  Educational reference");
        setText(
            g_controls.ggh_fingerprint,
            "  Fingerprint: " + g_state.ggh->public_fingerprint);

        appendLog(
            "GGH key generated in " +
            durationText(*g_state.timings.ggh_keygen));

        updateBenchmarks();
        updateDetails();
    } catch (const exception& error) {
        appendLog(string("GGH key generation failed: ") + error.what());
        showError(window, error.what());
    }
}

void signCommand(HWND window) {
    if (!g_state.rsa || !g_state.ggh) {
        showError(window, "Generate both RSA-4096 and GGH keys before signing.");
        return;
    }

    try {
        const string command = narrow(controlText(g_controls.command));

        if (command.empty()) {
            showError(window, "Command cannot be empty.");
            return;
        }

        hybrid_pki::CommandEnvelope envelope{
            command,
            nowUtc(),
            g_state.next_sequence++
        };

        setText(
            g_controls.timestamp,
            "  Timestamp (UTC):  " + envelope.timestamp_utc +
            "   |   Local: " + clockTime());
        setText(
            g_controls.sequence,
            "  Sequence / nonce: " + to_string(envelope.sequence));

        appendLog("Signing command: " + envelope.command);

        auto result =
            hybrid_pki::hybridSign(envelope, *g_state.rsa, *g_state.ggh);

        g_state.signed_command = result.signed_command;
        g_state.original_signed_command = result.signed_command;
        g_state.timings.sign = result.measurements;
        g_state.has_signed_command = true;
        g_state.tampered = false;

        resetVerification();
        updateSignatureInfo();
        updateDetails();
        updateBenchmarks();

        appendLog("RSA signed in " + durationText(result.measurements.rsa));
        appendLog("GGH signed in " + durationText(result.measurements.ggh));
        appendLog(
            "Hybrid signature created in " +
            durationText(result.measurements.hybrid));
    } catch (const exception& error) {
        appendLog(string("Signing failed: ") + error.what());
        showError(window, error.what());
    }
}

void verifyCommand(HWND window) {
    if (!requireSigned(window) || !g_state.rsa || !g_state.ggh) return;

    try {
        const auto result =
            hybrid_pki::hybridVerify(
                g_state.signed_command, *g_state.rsa, *g_state.ggh);

        g_state.timings.verify = result.measurements;

        const string rsa = result.rsa_valid ? "PASS" : "FAIL";
        const string ggh = result.ggh_valid ? "PASS" : "FAIL";
        const string overall =
            result.overall_valid ? "VALID" : "INVALID";

        ostringstream display;
        display << "  RSA verification:     " << rsa << "\r\n"
                << "  GGH verification:     " << ggh << "\r\n"
                << "  Hybrid result:        " << overall;

        setText(g_controls.verification, display.str());

        appendLog("RSA verification: " + rsa);
        appendLog("GGH verification: " + ggh);
        appendLog("Hybrid result: " + overall);

        updateBenchmarks();
        updateSignatureInfo();
    } catch (const exception& error) {
        appendLog(string("Verification failed: ") + error.what());
        showError(window, error.what());
    }
}

void runFullBenchmark(HWND window) {
    try {
        appendLog("Running full benchmark suite.");

        const auto rsaStart = chrono::steady_clock::now();
        auto rsaBench = hybrid_pki::generateRSAKeyPair();
        const auto rsaEnd = chrono::steady_clock::now();

        g_state.timings.rsa_keygen =
            chrono::duration_cast<chrono::nanoseconds>(rsaEnd - rsaStart);

        const auto gghStart = chrono::steady_clock::now();
        auto gghBench = hybrid_pki::generateGGHKeyPair();
        const auto gghEnd = chrono::steady_clock::now();

        g_state.timings.ggh_keygen =
            chrono::duration_cast<chrono::nanoseconds>(gghEnd - gghStart);

        auto& rsaKey = g_state.rsa ? *g_state.rsa : rsaBench;
        auto& gghKey = g_state.ggh ? *g_state.ggh : gghBench;

        hybrid_pki::CommandEnvelope envelope{
            "BENCHMARK_TEST",
            nowUtc(),
            0
        };

        const auto signResult =
            hybrid_pki::hybridSign(envelope, rsaKey, gghKey);

        const auto verifyResult =
            hybrid_pki::hybridVerify(
                signResult.signed_command, rsaKey, gghKey);

        g_state.timings.sign = signResult.measurements;
        g_state.timings.verify = verifyResult.measurements;

        appendLog(
            "RSA keygen:      " +
            durationText(*g_state.timings.rsa_keygen));
        appendLog(
            "GGH keygen:      " +
            durationText(*g_state.timings.ggh_keygen));
        appendLog(
            "RSA sign:        " +
            durationText(signResult.measurements.rsa));
        appendLog(
            "GGH sign:        " +
            durationText(signResult.measurements.ggh));
        appendLog(
            "Hybrid sign:     " +
            durationText(signResult.measurements.hybrid));
        appendLog(
            "RSA verify:      " +
            durationText(verifyResult.measurements.rsa));
        appendLog(
            "GGH verify:      " +
            durationText(verifyResult.measurements.ggh));
        appendLog(
            "Hybrid verify:   " +
            durationText(verifyResult.measurements.hybrid));

        updateBenchmarks();

        appendLog(
            verifyResult.overall_valid
                ? "Benchmark verification passed."
                : "WARNING: benchmark verification failed.");

        appendLog("Benchmark complete.");
    } catch (const exception& error) {
        appendLog(string("Benchmark failed: ") + error.what());
        showError(window, error.what());
    }
}

void updateEnvelopeControls() {
    if (!g_state.has_signed_command) return;

    setText(
        g_controls.command,
        g_state.signed_command.envelope.command);

    setText(
        g_controls.timestamp,
        "  Timestamp (UTC):  " +
        g_state.signed_command.envelope.timestamp_utc +
        "   |   Local: " + clockTime());

    setText(
        g_controls.sequence,
        "  Sequence / nonce: " +
        to_string(g_state.signed_command.envelope.sequence));
}

bool endsWith(const string& value, const string& suffix) {
    return value.size() >= suffix.size() &&
           value.compare(
               value.size() - suffix.size(),
               suffix.size(),
               suffix) == 0;
}

void refreshTamperState() {
    if (!g_state.has_signed_command) {
        g_state.tampered = false;
        return;
    }

    const auto& current = g_state.signed_command;
    const auto& original = g_state.original_signed_command;

    g_state.tampered =
        current.envelope.command != original.envelope.command ||
        current.envelope.timestamp_utc != original.envelope.timestamp_utc ||
        current.envelope.sequence != original.envelope.sequence ||
        current.rsa_signature != original.rsa_signature ||
        current.ggh_signature.lattice_point !=
            original.ggh_signature.lattice_point;
}

void tamper(HWND window, const int operation) {
    if (!requireSigned(window)) return;

    switch (operation) {
        case kModifyCommand: {
            constexpr const char* marker = " [TAMPERED]";

            if (endsWith(g_state.signed_command.envelope.command, marker)) {
                g_state.signed_command.envelope.command.erase(
                    g_state.signed_command.envelope.command.size() -
                    string(marker).size());
            } else {
                g_state.signed_command.envelope.command += marker;
            }

            appendLog("TAMPER: command modified; signatures retained.");
            break;
        }

        case kModifyTimestamp:
            g_state.signed_command.envelope.timestamp_utc =
                g_state.signed_command.envelope.timestamp_utc ==
                        "1970-01-01T00:00:00Z"
                    ? g_state.original_signed_command.envelope.timestamp_utc
                    : "1970-01-01T00:00:00Z";
            appendLog("TAMPER: timestamp changed; signatures retained.");
            break;

        case kModifySequence:
            if (g_state.signed_command.envelope.sequence ==
                g_state.original_signed_command.envelope.sequence) {
                ++g_state.signed_command.envelope.sequence;
            } else {
                g_state.signed_command.envelope.sequence =
                    g_state.original_signed_command.envelope.sequence;
            }
            appendLog("TAMPER: sequence changed; signatures retained.");
            break;

        case kCorruptRsa:
            if (!g_state.signed_command.rsa_signature.empty()) {
                g_state.signed_command.rsa_signature.front() ^= 0x01U;
                appendLog("TAMPER: RSA signature bit flipped.");
            }
            break;

        case kCorruptGgh:
            if (!g_state.signed_command.ggh_signature.lattice_point.empty()) {
                g_state.signed_command.ggh_signature.lattice_point.front() ^= 1LL;
                appendLog("TAMPER: GGH signature bit flipped.");
            }
            break;

        default:
            return;
    }

    refreshTamperState();
    resetVerification();
    updateEnvelopeControls();
    updateDetails();
    updateSignatureInfo();
}

void resetTamper() {
    if (!g_state.has_signed_command) return;

    g_state.signed_command = g_state.original_signed_command;
    g_state.tampered = false;

    updateEnvelopeControls();
    resetVerification();
    updateDetails();
    updateSignatureInfo();

    appendLog("Tamper state reset to the original signed payload.");
}

void drawRoundedCard(HDC dc, const RECT& rect) {
    SelectObject(dc, g_border_pen);
    SelectObject(dc, g_card_brush);

    RoundRect(
        dc,
        rect.left, rect.top,
        rect.right, rect.bottom,
        12, 12);
}

void drawSectionLabel(
    HDC dc, const int x, const int y,
    const wchar_t* text, const COLORREF color) {

    SetTextColor(dc, color);
    SetBkMode(dc, TRANSPARENT);
    SelectObject(dc, g_label_font);

    TextOutW(
        dc, x, y, text,
        static_cast<int>(wcslen(text)));
}

Layout calculateLayout(const int width, const int height) {
    Layout layout{};

    const int contentTop = kHeaderHeight + kMargin;
    const int footerTop = height - kFooterHeight;
    const int contentBottom = footerTop - kMargin;

    const int availableWidth = width - 2 * kMargin - kGap;
    const int leftWidth = availableWidth * 45 / 100;
    const int rightWidth = availableWidth - leftWidth;

    const int leftX = kMargin;
    const int rightX = leftX + leftWidth + kGap;

    layout.keys = {
        leftX, contentTop,
        leftX + leftWidth, contentTop + 220
    };

    layout.signature = {
        leftX,
        layout.keys.bottom + kGap,
        leftX + leftWidth,
        layout.keys.bottom + kGap + 142
    };

    layout.details = {
        leftX,
        layout.signature.bottom + kGap,
        leftX + leftWidth,
        contentBottom
    };

    layout.command = {
        rightX,
        contentTop,
        rightX + rightWidth,
        contentTop + 188
    };

    layout.verification = {
        rightX,
        layout.command.bottom + kGap,
        rightX + rightWidth,
        layout.command.bottom + kGap + 102
    };

    layout.benchmarks = {
        rightX,
        layout.verification.bottom + kGap,
        rightX + rightWidth,
        layout.verification.bottom + kGap + 226
    };

    layout.log = {
        rightX,
        layout.benchmarks.bottom + kGap,
        rightX + rightWidth,
        contentBottom
    };

    layout.tamper = {
        kMargin,
        footerTop + 8,
        width - kMargin,
        height - kMargin
    };

    return layout;
}

void moveControl(HWND control, const RECT& rect) {
    if (!control) return;

    const int width = static_cast<int>(rect.right - rect.left);
    const int height = static_cast<int>(rect.bottom - rect.top);

    SetWindowPos(
        control, nullptr,
        static_cast<int>(rect.left),
        static_cast<int>(rect.top),
        max(1, width),
        max(1, height),
        SWP_NOZORDER | SWP_NOACTIVATE);
}

void layoutControls(HWND window) {
    RECT client{};
    GetClientRect(window, &client);

    const Layout layout =
        calculateLayout(client.right, client.bottom);

    const int innerLeft = layout.keys.left + kCardPad;
    const int leftWidth =
        layout.keys.right - layout.keys.left - 2 * kCardPad;

    moveControl(
        g_controls.rsa_status,
        {innerLeft, layout.keys.top + 28,
         innerLeft + leftWidth, layout.keys.top + 50});

    moveControl(
        g_controls.rsa_fingerprint,
        {innerLeft, layout.keys.top + 53,
         innerLeft + leftWidth, layout.keys.top + 74});

    moveControl(
        GetDlgItem(window, kRsaGenerate),
        {innerLeft, layout.keys.top + 82,
         innerLeft + leftWidth, layout.keys.top + 116});

    moveControl(
        g_controls.ggh_status,
        {innerLeft, layout.keys.top + 128,
         innerLeft + leftWidth, layout.keys.top + 150});

    moveControl(
        g_controls.ggh_fingerprint,
        {innerLeft, layout.keys.top + 153,
         innerLeft + leftWidth, layout.keys.top + 174});

    moveControl(
        GetDlgItem(window, kGghGenerate),
        {innerLeft, layout.keys.top + 174,
         innerLeft + leftWidth, layout.keys.top + 208});

    moveControl(
        g_controls.signature_info,
        {layout.signature.left + kCardPad,
         layout.signature.top + 28,
         layout.signature.right - kCardPad,
         layout.signature.bottom - kCardPad});

    moveControl(
        g_controls.details,
        {layout.details.left + kCardPad,
         layout.details.top + 28,
         layout.details.right - kCardPad,
         layout.details.bottom - kCardPad});

    const int rightLeft = layout.command.left + kCardPad;
    const int rightWidth =
        layout.command.right - layout.command.left - 2 * kCardPad;

    moveControl(
        g_controls.command,
        {rightLeft, layout.command.top + 30,
         rightLeft + rightWidth, layout.command.top + 62});

    moveControl(
        g_controls.timestamp,
        {rightLeft, layout.command.top + 72,
         rightLeft + rightWidth, layout.command.top + 94});

    moveControl(
        g_controls.sequence,
        {rightLeft, layout.command.top + 98,
         rightLeft + rightWidth, layout.command.top + 120});

    const int actionGap = 10;
    const int actionWidth = (rightWidth - actionGap) / 2;

    moveControl(
        GetDlgItem(window, kSign),
        {rightLeft, layout.command.top + 132,
         rightLeft + actionWidth, layout.command.top + 168});

    moveControl(
        GetDlgItem(window, kVerify),
        {rightLeft + actionWidth + actionGap,
         layout.command.top + 132,
         rightLeft + rightWidth,
         layout.command.top + 168});

    moveControl(
        g_controls.verification,
        {layout.verification.left + kCardPad,
         layout.verification.top + 28,
         layout.verification.right - kCardPad,
         layout.verification.bottom - kCardPad});

    moveControl(
        g_controls.benchmarks,
        {layout.benchmarks.left + kCardPad,
         layout.benchmarks.top + 28,
         layout.benchmarks.right - kCardPad,
         layout.benchmarks.bottom - 54});

    moveControl(
        GetDlgItem(window, kRunBenchmark),
        {layout.benchmarks.left + kCardPad,
         layout.benchmarks.bottom - 44,
         layout.benchmarks.right - kCardPad,
         layout.benchmarks.bottom - 12});

    moveControl(
        g_controls.event_log,
        {layout.log.left + kCardPad,
         layout.log.top + 28,
         layout.log.right - kCardPad,
         layout.log.bottom - kCardPad});

    const int tamperGap = 8;
    const int tamperCount = 6;
    const int tamperAvailableWidth =
        static_cast<int>(layout.tamper.right - layout.tamper.left);

    const int tamperWidth =
        max(100,
            (tamperAvailableWidth -
             tamperGap * (tamperCount - 1)) / tamperCount);

    const int tamperIds[tamperCount] = {
        kModifyCommand,
        kModifyTimestamp,
        kModifySequence,
        kCorruptRsa,
        kCorruptGgh,
        kResetTamper
    };

    for (int i = 0; i < tamperCount; ++i) {
        const int x =
            layout.tamper.left +
            i * (tamperWidth + tamperGap);

        moveControl(
            GetDlgItem(window, tamperIds[i]),
            {x, layout.tamper.top,
             x + tamperWidth,
             layout.tamper.bottom});
    }
}

HWND makeControl(
    const wchar_t* type,
    const wchar_t* text,
    DWORD style,
    int id,
    HWND parent,
    HFONT font,
    DWORD exStyle = 0) {

    HWND control = CreateWindowExW(
        exStyle, type, text, style,
        0, 0, 0, 0,
        parent,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
        GetModuleHandleW(nullptr),
        nullptr);

    if (control) {
        SendMessageW(
            control, WM_SETFONT,
            reinterpret_cast<WPARAM>(font), TRUE);
    }

    return control;
}

HWND makeButton(const wchar_t* text, const int id, HWND parent) {
    return makeControl(
        L"BUTTON", text,
        WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
        id, parent, g_btn_font);
}

void destroyBackBuffer() {
    if (g_back_dc) {
        DeleteDC(g_back_dc);
        g_back_dc = nullptr;
    }

    if (g_back_buffer) {
        DeleteObject(g_back_buffer);
        g_back_buffer = nullptr;
    }

    g_back_width = 0;
    g_back_height = 0;
}

bool ensureBackBuffer(HDC windowDc, const int width, const int height) {
    if (width <= 0 || height <= 0) return false;

    if (g_back_dc &&
        g_back_buffer &&
        g_back_width == width &&
        g_back_height == height) {
        return true;
    }

    destroyBackBuffer();

    g_back_dc = CreateCompatibleDC(windowDc);
    if (!g_back_dc) return false;

    g_back_buffer = CreateCompatibleBitmap(windowDc, width, height);
    if (!g_back_buffer) {
        destroyBackBuffer();
        return false;
    }

    SelectObject(g_back_dc, g_back_buffer);
    g_back_width = width;
    g_back_height = height;
    return true;
}

void drawHeaderBar(HDC dc, const int width);
void drawFooter(HDC dc, const RECT& rect);
void drawCards(HDC dc, const Layout& layout);

void paintDashboard(HDC dc, const int width, const int height) {
    RECT client{0, 0, width, height};
    FillRect(dc, &client, g_bg_brush);

    drawHeaderBar(dc, width);

    const Layout layout = calculateLayout(width, height);
    drawCards(dc, layout);
    drawFooter(dc, layout.tamper);
}

void drawHeaderBar(HDC dc, const int width) {
    RECT header{0, 0, width, kHeaderHeight};
    FillRect(dc, &header, g_card_brush);

    SetBkMode(dc, TRANSPARENT);

    SetTextColor(dc, kAccentTeal);
    SelectObject(dc, g_title_font);
    TextOutW(dc, kMargin, 13, L"HYBRID PKI", 10);

    SetTextColor(dc, kTextBright);
    SelectObject(dc, g_heading_font);
    TextOutW(
        dc, kMargin, 43,
        L"SCADA COMMAND SIGNING  |  RSA-4096 + GGH",
        39);

    const wstring timeText = widen("LIVE LOCAL " + clockTime());

    SIZE size{};
    GetTextExtentPoint32W(
        dc, timeText.c_str(),
        static_cast<int>(timeText.size()), &size);

    SetTextColor(dc, kTextMuted);
    SelectObject(dc, g_mono_font);

    TextOutW(
        dc,
        max(kMargin, width - kMargin - static_cast<int>(size.cx)),
        30,
        timeText.c_str(),
        static_cast<int>(timeText.size()));

    SelectObject(dc, g_accent_pen);
    MoveToEx(dc, 0, kHeaderHeight - 1, nullptr);
    LineTo(dc, width, kHeaderHeight - 1);
}

void drawFooter(HDC dc, const RECT& rect) {
    HBRUSH footerBrush = CreateSolidBrush(kBgHeader);
    FillRect(dc, &rect, footerBrush);
    DeleteObject(footerBrush);

    drawSectionLabel(
        dc,
        rect.left,
        rect.top - 18,
        L"TAMPERING / NEGATIVE TESTS",
        kWarning);
}

void drawCards(HDC dc, const Layout& layout) {
    drawRoundedCard(dc, layout.keys);
    drawRoundedCard(dc, layout.signature);
    drawRoundedCard(dc, layout.details);
    drawRoundedCard(dc, layout.command);
    drawRoundedCard(dc, layout.verification);
    drawRoundedCard(dc, layout.benchmarks);
    drawRoundedCard(dc, layout.log);

    drawSectionLabel(
        dc, layout.keys.left, layout.keys.top - 18,
        L"KEY MANAGEMENT", kAccentTeal);

    drawSectionLabel(
        dc, layout.signature.left, layout.signature.top - 18,
        L"SIGNATURE PAYLOAD", kAccentTeal);

    drawSectionLabel(
        dc, layout.details.left, layout.details.top - 18,
        L"CANONICAL MESSAGE", kAccentTeal);

    drawSectionLabel(
        dc, layout.command.left, layout.command.top - 18,
        L"COMMAND", kAccentTeal);

    drawSectionLabel(
        dc, layout.verification.left, layout.verification.top - 18,
        L"VERIFICATION", kAccentTeal);

    drawSectionLabel(
        dc, layout.benchmarks.left, layout.benchmarks.top - 18,
        L"BENCHMARKS", kAccentTeal);

    drawSectionLabel(
        dc, layout.log.left, layout.log.top - 18,
        L"EVENT LOG", kAccentTeal);
}

void createFontsAndBrushes() {
    g_title_font = CreateFontW(
        24, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
        DEFAULT_PITCH, L"Segoe UI");

    g_heading_font = CreateFontW(
        15, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
        DEFAULT_PITCH, L"Segoe UI");

    g_body_font = CreateFontW(
        14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
        DEFAULT_PITCH, L"Segoe UI");

    g_mono_font = CreateFontW(
        13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
        FIXED_PITCH, L"Cascadia Mono");

    g_label_font = CreateFontW(
        12, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
        DEFAULT_PITCH, L"Segoe UI");

    g_btn_font = CreateFontW(
        13, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
        DEFAULT_PITCH, L"Segoe UI");

    g_bg_brush = CreateSolidBrush(kBgDeep);
    g_card_brush = CreateSolidBrush(kBgCard);
    g_field_brush = CreateSolidBrush(kBgField);
    g_btn_brush = CreateSolidBrush(kBtnFace);

    g_border_pen = CreatePen(PS_SOLID, 1, kBorder);
    g_accent_pen = CreatePen(PS_SOLID, 2, kAccentTeal);
}

void destroyGdiResources() {
    const HGDIOBJ objects[] = {
        g_title_font, g_heading_font, g_body_font,
        g_mono_font, g_label_font, g_btn_font,
        g_bg_brush, g_card_brush, g_field_brush,
        g_btn_brush, g_border_pen, g_accent_pen
    };

    for (const HGDIOBJ object : objects) {
        if (object) DeleteObject(object);
    }
}

LRESULT CALLBACK windowProcedure(
    HWND window,
    UINT message,
    WPARAM wparam,
    LPARAM lparam) {

    switch (message) {
        case WM_CREATE: {
            createFontsAndBrushes();

            g_controls.rsa_status = makeControl(
                L"STATIC",
                L"  RSA-4096:  NOT GENERATED",
                WS_CHILD | WS_VISIBLE,
                0, window, g_body_font);

            g_controls.rsa_fingerprint = makeControl(
                L"STATIC",
                L"  Fingerprint: --",
                WS_CHILD | WS_VISIBLE,
                0, window, g_body_font);

            makeButton(
                L"GENERATE RSA-4096 KEY",
                kRsaGenerate, window);

            g_controls.ggh_status = makeControl(
                L"STATIC",
                L"  GGH n=16:  NOT GENERATED",
                WS_CHILD | WS_VISIBLE,
                0, window, g_body_font);

            g_controls.ggh_fingerprint = makeControl(
                L"STATIC",
                L"  Fingerprint: --",
                WS_CHILD | WS_VISIBLE,
                0, window, g_body_font);

            makeButton(
                L"GENERATE GGH KEY",
                kGghGenerate, window);

            g_controls.command = makeControl(
                L"EDIT",
                L"OPEN_VALVE",
                WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL |
                    ES_LEFT | WS_TABSTOP,
                0, window, g_body_font,
                WS_EX_CLIENTEDGE);

            g_controls.timestamp = makeControl(
                L"STATIC",
                L"  Timestamp (UTC): captured when SIGN is pressed",
                WS_CHILD | WS_VISIBLE,
                0, window, g_body_font);

            g_controls.sequence = makeControl(
                L"STATIC",
                L"  Sequence / nonce: auto on SIGN",
                WS_CHILD | WS_VISIBLE,
                0, window, g_body_font);

            makeButton(L"SIGN COMMAND", kSign, window);
            makeButton(L"VERIFY COMMAND", kVerify, window);

            g_controls.verification = makeControl(
                L"STATIC",
                L"  RSA verification:     PENDING\r\n"
                L"  GGH verification:     PENDING\r\n"
                L"  Hybrid result:        PENDING",
                WS_CHILD | WS_VISIBLE,
                0, window, g_heading_font);

            g_controls.signature_info = makeControl(
                L"STATIC",
                L"  No hybrid command has been signed yet.\r\n"
                L"  Generate both keys and sign a command to view signature data.",
                WS_CHILD | WS_VISIBLE,
                0, window, g_body_font);

            g_controls.details = makeControl(
                L"EDIT",
                L"",
                WS_CHILD | WS_VISIBLE | ES_MULTILINE |
                    ES_READONLY | WS_VSCROLL | ES_AUTOVSCROLL,
                0, window, g_mono_font,
                WS_EX_CLIENTEDGE);

            g_controls.benchmarks = makeControl(
                L"STATIC",
                L"",
                WS_CHILD | WS_VISIBLE,
                0, window, g_mono_font);

            makeButton(
                L"RUN FULL BENCHMARK",
                kRunBenchmark, window);

            g_controls.event_log = makeControl(
                L"EDIT",
                L"",
                WS_CHILD | WS_VISIBLE | ES_MULTILINE |
                    ES_READONLY | WS_VSCROLL | ES_AUTOVSCROLL,
                0, window, g_mono_font,
                WS_EX_CLIENTEDGE);

            makeButton(L"MODIFY CMD", kModifyCommand, window);
            makeButton(L"MODIFY TIME", kModifyTimestamp, window);
            makeButton(L"MODIFY SEQ", kModifySequence, window);
            makeButton(L"CORRUPT RSA", kCorruptRsa, window);
            makeButton(L"CORRUPT GGH", kCorruptGgh, window);
            makeButton(L"RESET TAMPER", kResetTamper, window);

            layoutControls(window);
            updateDetails();
            updateBenchmarks();
            resetVerification();

            SetTimer(window, kClockTimer, 1000, nullptr);

            appendLog("Dashboard initialized.");
            appendLog("System clock is live; signing captures UTC at runtime.");
            return 0;
        }

        case WM_TIMER:
            if (wparam == kClockTimer) {
                RECT clockRect{};
                // Only the small live-clock area is repainted.
                // The full window is intentionally NOT invalidated.
                RECT client{};
                GetClientRect(window, &client);
                clockRect.left = max(0L, client.right - 260L);
                clockRect.top = 8;
                clockRect.right = client.right - 8;
                clockRect.bottom = 62;
                InvalidateRect(window, &clockRect, FALSE);
            }
            return 0;

        case WM_SIZE:
            layoutControls(window);
            InvalidateRect(window, nullptr, FALSE);
            return 0;

        case WM_COMMAND:
            if (HIWORD(wparam) == BN_CLICKED) {
                switch (LOWORD(wparam)) {
                    case kRsaGenerate:
                        generateRsa(window);
                        break;
                    case kGghGenerate:
                        generateGgh(window);
                        break;
                    case kSign:
                        signCommand(window);
                        break;
                    case kVerify:
                        verifyCommand(window);
                        break;
                    case kRunBenchmark:
                        runFullBenchmark(window);
                        break;
                    case kModifyCommand:
                    case kModifyTimestamp:
                    case kModifySequence:
                    case kCorruptRsa:
                    case kCorruptGgh:
                        tamper(window, LOWORD(wparam));
                        break;
                    case kResetTamper:
                        resetTamper();
                        break;
                    default:
                        break;
                }
            }
            return 0;

        case WM_DRAWITEM: {
            const auto* draw =
                reinterpret_cast<const DRAWITEMSTRUCT*>(lparam);

            if (!draw || draw->CtlType != ODT_BUTTON) {
                return 0;
            }

            const int id = static_cast<int>(draw->CtlID);
            const bool primary = isPrimaryButton(id);
            const bool disabled =
                (draw->itemState & ODS_DISABLED) != 0;
            const bool focused =
                (draw->itemState & ODS_FOCUS) != 0;

            HBRUSH fill = CreateSolidBrush(
                disabled
                    ? RGB(38, 45, 56)
                    : primary
                        ? RGB(28, 154, 137)
                        : kBtnFace);

            HPEN border = CreatePen(
                PS_SOLID,
                1,
                primary ? kAccentTeal : kBorder);

            SelectObject(draw->hDC, fill);
            SelectObject(draw->hDC, border);

            RECT r = draw->rcItem;
            InflateRect(&r, -1, -1);

            RoundRect(
                draw->hDC,
                r.left, r.top,
                r.right, r.bottom,
                8, 8);

            SetBkMode(draw->hDC, TRANSPARENT);
            SetTextColor(
                draw->hDC,
                disabled
                    ? kTextMuted
                    : primary
                        ? RGB(245, 255, 252)
                        : kTextBright);

            SelectObject(draw->hDC, g_btn_font);

            wchar_t text[256]{};
            GetWindowTextW(
                draw->hwndItem,
                text,
                static_cast<int>(sizeof(text) / sizeof(text[0])));

            DrawTextW(
                draw->hDC,
                text,
                -1,
                &r,
                DT_CENTER | DT_VCENTER | DT_SINGLELINE);

            if (focused && !disabled) {
                RECT focus = r;
                InflateRect(&focus, -4, -4);
                DrawFocusRect(draw->hDC, &focus);
            }

            DeleteObject(fill);
            DeleteObject(border);
            return TRUE;
        }

        case WM_PAINT: {
            PAINTSTRUCT paint{};
            HDC dc = BeginPaint(window, &paint);

            RECT client{};
            GetClientRect(window, &client);

            if (ensureBackBuffer(dc, client.right, client.bottom)) {
                paintDashboard(
                    g_back_dc,
                    client.right,
                    client.bottom);

                BitBlt(
                    dc,
                    paint.rcPaint.left,
                    paint.rcPaint.top,
                    paint.rcPaint.right - paint.rcPaint.left,
                    paint.rcPaint.bottom - paint.rcPaint.top,
                    g_back_dc,
                    paint.rcPaint.left,
                    paint.rcPaint.top,
                    SRCCOPY);
            } else {
                paintDashboard(dc, client.right, client.bottom);
            }

            EndPaint(window, &paint);
            return 0;
        }

        case WM_CTLCOLORSTATIC: {
            HDC dc = reinterpret_cast<HDC>(wparam);
            HWND control = reinterpret_cast<HWND>(lparam);

            SetBkMode(dc, TRANSPARENT);

            if (control == g_controls.verification) {
                wchar_t buffer[256]{};
                GetWindowTextW(control, buffer, 256);
                const wstring text(buffer);

                if (text.find(L"FAIL") != wstring::npos ||
                    text.find(L"INVALID") != wstring::npos) {
                    SetTextColor(dc, kFailure);
                } else if (
                    text.find(L"PASS") != wstring::npos ||
                    text.find(L"VALID") != wstring::npos) {
                    SetTextColor(dc, kSuccess);
                } else {
                    SetTextColor(dc, kTextMuted);
                }
            } else if (
                control == g_controls.rsa_status ||
                control == g_controls.ggh_status) {

                wchar_t buffer[256]{};
                GetWindowTextW(control, buffer, 256);
                const wstring text(buffer);

                SetTextColor(
                    dc,
                    text.find(L"GENERATED") != wstring::npos
                        ? kSuccess
                        : kTextMuted);
            } else {
                SetTextColor(dc, kTextBright);
            }

            // Opaque card background prevents stale text pixels when a
            // STATIC control's content changes to a shorter string.
            SetBkColor(dc, kBgCard);
            return reinterpret_cast<LRESULT>(g_card_brush);
        }

        case WM_CTLCOLOREDIT: {
            HDC dc = reinterpret_cast<HDC>(wparam);

            SetTextColor(dc, kTextBright);
            SetBkColor(dc, kBgField);

            return reinterpret_cast<LRESULT>(g_field_brush);
        }

        case WM_ERASEBKGND:
            return 1;

        case WM_GETMINMAXINFO: {
            auto* info =
                reinterpret_cast<MINMAXINFO*>(lparam);

            info->ptMinTrackSize.x = kMinWidth;
            info->ptMinTrackSize.y = kMinHeight;
            return 0;
        }

        case WM_DESTROY:
            KillTimer(window, kClockTimer);
            destroyBackBuffer();
            destroyGdiResources();
            PostQuitMessage(0);
            return 0;

        default:
            return DefWindowProcW(
                window, message, wparam, lparam);
    }
}

}

int WINAPI wWinMain(
    HINSTANCE instance,
    HINSTANCE,
    PWSTR,
    int commandShow) {

    INITCOMMONCONTROLSEX controls{
        sizeof(controls),
        ICC_STANDARD_CLASSES
    };

    InitCommonControlsEx(&controls);

    const wchar_t* className =
        L"HybridPkiScadaCryptoGui";

    WNDCLASSW windowClass{};
    windowClass.hInstance = instance;
    windowClass.lpszClassName = className;
    windowClass.lpfnWndProc = windowProcedure;
    windowClass.hCursor =
        LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = nullptr;

    if (!RegisterClassW(&windowClass) &&
        GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        return 1;
    }

    HWND window = CreateWindowExW(
        WS_EX_COMPOSITED,
        className,
        L"HYBRID PKI - SCADA CRYPTOGRAPHY",
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        1280,
        900,
        nullptr,
        nullptr,
        instance,
        nullptr);

    if (!window) return 1;

    ShowWindow(window, commandShow);
    UpdateWindow(window);

    MSG message{};

    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }

    return static_cast<int>(message.wParam);
}
