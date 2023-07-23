// Not fully functional as
// the program can still be tampered with
// or with just basic ring0 access, the target process can be removed from the EPROCESS list and thus would not be found

#include <iostream>
#include <Windows.h>
#include <Wincrypt.h>
#pragma comment(lib, "crypt32.lib")

bool has_valid_certificate(DWORD process_id) {
    bool has_valid_cert = false;

    HANDLE h_process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, process_id);
    if (h_process != NULL) {
        HMODULE h_module;
        DWORD cb_needed;
        if (EnumProcessModules(h_process, &h_module, sizeof(h_module), &cb_needed)) {
            BYTE* image_buffer = new BYTE[cb_needed];
            if (GetModuleInformation(h_process, h_module, reinterpret_cast<MODULEINFO*>(image_buffer), cb_needed)) {
                WINTRUST_FILE_INFO file_data;
                memset(&file_data, 0, sizeof(file_data));
                file_data.cbStruct = sizeof(file_data);
                file_data.pcwszFilePath = reinterpret_cast<LPCWSTR>(image_buffer);

                WINTRUST_DATA wintrust_data;
                memset(&wintrust_data, 0, sizeof(wintrust_data));
                wintrust_data.cbStruct = sizeof(wintrust_data);
                wintrust_data.pFile = &file_data;
                wintrust_data.dwUIChoice = WTD_UI_NONE;
                wintrust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
                wintrust_data.dwUnionChoice = WTD_CHOICE_FILE;

                LONG l_status = WinVerifyTrust(NULL, &WintrustActionGenericVerifyV2, &wintrust_data);
                if (l_status == ERROR_SUCCESS) {
                    has_valid_cert = true;
                }
            }
            delete[] image_buffer;
        }
        CloseHandle(h_process);
    }

    return has_valid_cert;
}

int main() {
    DWORD processes[1024];
    DWORD cb_needed;

    if (EnumProcesses(processes, sizeof(processes), &cb_needed)) {
        int num_processes = cb_needed / sizeof(DWORD);
        for (int i = 0; i < num_processes; i++) {
            DWORD process_id = processes[i];
            if (has_valid_certificate(process_id)) {
                std::cout << "[only-certs] Process ID " << process_id << " has a valid certificate." << std::endl;
            } else {
                std::cout << "[only-certs] Process ID " << process_id << " does not have a valid certificate." << std::endl;
            }
        }
    } else {
        std::cout << "[only-certs] Failed to enumerate processes." << std::endl;
    }

    return 0;
}
