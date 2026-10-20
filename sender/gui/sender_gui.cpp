#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shellapi.h>

#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "http_bridge.hpp"
#include "../machines/machine_manager.hpp"
#include "../messaging/message_store.hpp"
#include "../storage/local_storage.hpp"

using namespace std;

namespace {

string getStoragePath() {
    char path[MAX_PATH]{};
    GetModuleFileNameA(nullptr, path, MAX_PATH);
    string exe_dir(path);
    auto last_sep = exe_dir.find_last_of("\\/");
    if (last_sep != string::npos) exe_dir = exe_dir.substr(0, last_sep);
    return exe_dir + "\\sender_data";
}

string findAssetsDir() {
    char path[MAX_PATH]{};
    GetModuleFileNameA(nullptr, path, MAX_PATH);
    string exe_dir(path);
    auto last_sep = exe_dir.find_last_of("\\/");
    if (last_sep != string::npos) exe_dir = exe_dir.substr(0, last_sep);

    vector<string> candidates = {
        exe_dir + "\\..\\sender\\ui",
        "sender\\ui",
        exe_dir + "\\ui",
        ".\\ui",
        exe_dir + "\\..\\..\\sender\\ui"
    };

    for (const auto& c : candidates) {
        string test_file = c + "\\index.html";
        DWORD attrib = GetFileAttributesA(test_file.c_str());
        if (attrib != INVALID_FILE_ATTRIBUTES && !(attrib & FILE_ATTRIBUTE_DIRECTORY)) {
            return c;
        }
    }
    return exe_dir + "\\ui";
}

string findEdgePath() {
    vector<string> candidates = {
        "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe"
    };
    for (const auto& c : candidates) {
        if (GetFileAttributesA(c.c_str()) != INVALID_FILE_ATTRIBUTES) {
            return c;
        }
    }
    return "";
}

int runApp() {
    string storagePath = getStoragePath();
    sender::LocalStorage storage(storagePath);
    sender::MachineManager machines(storage);
    sender::MessageStore messages(storage);

    // Populate initial machines if list is empty
    if (machines.machines().empty()) {
        machines.addMachine("Test SCADA", "10.12.12.125", 502);
        machines.addMachine("Control Unit 02", "10.12.12.126", 502);
        machines.addMachine("Gateway North", "192.168.1.18", 502);
    }

    string assetsDir = findAssetsDir();
    sender::HttpBridge bridge(storage, machines, messages, assetsDir, 18443);
    if (!bridge.start()) {
        MessageBoxW(nullptr, L"Failed to start local C++ HTTP bridge server.", L"Hawk PKI SCADA", MB_OK | MB_ICONERROR);
        return 1;
    }

    string edgePath = findEdgePath();
    string url = bridge.rootUrl();
    string profileDir = storagePath + "\\web_profile";

    if (!edgePath.empty()) {
        // Launch Microsoft Edge in dedicated App Window Mode
        string cmdline = "\"" + edgePath + "\" --app=\"" + url + "\" --window-size=1280,840 --user-data-dir=\"" + profileDir + "\"";

        STARTUPINFOA si{};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};

        vector<char> cmdBuf(cmdline.begin(), cmdline.end());
        cmdBuf.push_back('\0');

        if (CreateProcessA(nullptr, cmdBuf.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
            WaitForSingleObject(pi.hProcess, INFINITE);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        } else {
            ShellExecuteA(nullptr, "open", url.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
        }
    } else {
        ShellExecuteA(nullptr, "open", url.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
    }

    bridge.stop();
    return 0;
}

}  // namespace

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    return runApp();
}

int main(int, char*[]) {
    return runApp();
}
