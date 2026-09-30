#include <windows.h>
#include "../CertificateManager.h"


CertificateManager manager;



LRESULT CALLBACK WindowProcedure(
    HWND hwnd,
    UINT msg,
    WPARAM wp,
    LPARAM lp
)
{

    switch(msg)
    {

        case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);


            // Certificate data
            manager.setCertificateInfo(
                "SCADA-Control-Center",
                "SCADA-Root-CA",
                "SCADA-001"
            );


            std::string title =
                "Hybrid PKI Manager - Person 2";


            std::string subject =
                "Subject: SCADA-Control-Center";


            std::string issuer =
                "Issuer: SCADA-Root-CA";


            std::string serial =
                "Serial Number: SCADA-001";


            std::string status;


            if(manager.validateCertificate())
            {
                status =
                    "Certificate Status: VALID";
            }
            else
            {
                status =
                    "Certificate Status: INVALID";
            }



            // Draw text on window

            TextOutA(
                hdc,
                50,
                50,
                title.c_str(),
                title.length()
            );


            TextOutA(
                hdc,
                50,
                100,
                subject.c_str(),
                subject.length()
            );


            TextOutA(
                hdc,
                50,
                130,
                issuer.c_str(),
                issuer.length()
            );


            TextOutA(
                hdc,
                50,
                160,
                serial.c_str(),
                serial.length()
            );


            TextOutA(
                hdc,
                50,
                210,
                status.c_str(),
                status.length()
            );


            EndPaint(hwnd, &ps);

            break;
        }



        case WM_DESTROY:

            PostQuitMessage(0);

            break;



        default:

            return DefWindowProcA(
                hwnd,
                msg,
                wp,
                lp
            );

    }


    return 0;
}





int WINAPI WinMain(
    HINSTANCE hInstance,
    HINSTANCE hPrevInstance,
    LPSTR lpCmdLine,
    int nCmdShow
)
{


    const char CLASS_NAME[] =
        "PKI_GUI";



    WNDCLASSA wc = {};

    wc.lpfnWndProc =
        WindowProcedure;

    wc.hInstance =
        hInstance;

    wc.lpszClassName =
        CLASS_NAME;



    RegisterClassA(&wc);




    HWND hwnd = CreateWindowExA(
        0,
        CLASS_NAME,
        "Hybrid PKI Manager - Person 2",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        600,
        400,
        NULL,
        NULL,
        hInstance,
        NULL
    );



    if(hwnd == NULL)
    {
        return 0;
    }



    ShowWindow(
        hwnd,
        nCmdShow
    );



    MSG msg = {};



    while(
        GetMessageA(
            &msg,
            NULL,
            0,
            0
        )
    )
    {

        TranslateMessage(&msg);

        DispatchMessageA(&msg);

    }



    return 0;
}