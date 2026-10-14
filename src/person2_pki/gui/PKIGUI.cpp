
#include <windows.h>
#include <string>

#include "../PKIManager.h"
#include "../CertificateManager.h"

PKIManager pki;
CertificateManager certificate;

bool certificateIssued = false;
bool certificateRevoked = false;

HWND statusLabel;
HWND detailsLabel;

#define ID_ISSUE    101
#define ID_VALIDATE 102
#define ID_REVOKE   103

void UpdateStatus(HWND hwnd)
{
    std::string status;

    if (!certificateIssued)
    {
        status = "Status: No certificate issued";
    }
    else
    {
        bool valid = pki.validateCertificate(
            certificate,
            "SCADA-002"
        );

        if (valid)
            status = "Status: VALID";
        else
            status = "Status: INVALID / REVOKED";
    }

    SetWindowTextA(statusLabel, status.c_str());

    std::string details =
        "Device: SCADA-PLC-01\n"
        "Issuer: SCADA-Root-CA\n"
        "Serial: SCADA-002";

    SetWindowTextA(detailsLabel, details.c_str());

    InvalidateRect(hwnd, NULL, TRUE);
}

LRESULT CALLBACK WindowProcedure(
    HWND hwnd,
    UINT msg,
    WPARAM wp,
    LPARAM lp
)
{
    switch (msg)
    {
        case WM_CREATE:
        {
            pki.initialize("SCADA-Root-CA", "CA-001");

            CreateWindowA(
                "BUTTON", "Issue Certificate",
                WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                30, 30, 180, 35,
                hwnd, (HMENU)ID_ISSUE,
                NULL, NULL
            );

            CreateWindowA(
                "BUTTON", "Validate Certificate",
                WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                230, 30, 190, 35,
                hwnd, (HMENU)ID_VALIDATE,
                NULL, NULL
            );

            CreateWindowA(
                "BUTTON", "Revoke Certificate",
                WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                440, 30, 180, 35,
                hwnd, (HMENU)ID_REVOKE,
                NULL, NULL
            );

            detailsLabel = CreateWindowA(
                "STATIC",
                "Device: Not issued yet",
                WS_VISIBLE | WS_CHILD,
                35, 105, 400, 90,
                hwnd, NULL, NULL, NULL
            );

            statusLabel = CreateWindowA(
                "STATIC",
                "Status: No certificate issued",
                WS_VISIBLE | WS_CHILD,
                35, 220, 500, 35,
                hwnd, NULL, NULL, NULL
            );

            return 0;
        }

        case WM_COMMAND:
        {
            switch (LOWORD(wp))
            {
                case ID_ISSUE:
                {
                    if (!certificateIssued)
                    {
                        certificate = pki.issueCertificate(
                            "SCADA-PLC-01",
                            "SCADA-002"
                        );

                        certificateIssued = true;
                        certificateRevoked = false;
                    }

                    UpdateStatus(hwnd);
                    return 0;
                }

                case ID_VALIDATE:
                {
                    UpdateStatus(hwnd);
                    return 0;
                }

                case ID_REVOKE:
                {
                    if (certificateIssued && !certificateRevoked)
                    {
                        pki.revokeCertificate("SCADA-002");
                        certificateRevoked = true;
                    }

                    UpdateStatus(hwnd);
                    return 0;
                }
            }

            break;
        }

        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }

    return DefWindowProcA(hwnd, msg, wp, lp);
}

int WINAPI WinMain(
    HINSTANCE hInstance,
    HINSTANCE,
    LPSTR,
    int nCmdShow
)
{
    const char CLASS_NAME[] = "PKI_GUI";

    WNDCLASSA wc = {};
    wc.lpfnWndProc = WindowProcedure;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);

    if (!RegisterClassA(&wc))
        return 1;

    HWND hwnd = CreateWindowExA(
        0,
        CLASS_NAME,
        "Hybrid PKI Manager - Person 2",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        680, 340,
        NULL, NULL, hInstance, NULL
    );

    if (!hwnd)
        return 1;

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg = {};

    while (GetMessageA(&msg, NULL, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

    return static_cast<int>(msg.wParam);
}
