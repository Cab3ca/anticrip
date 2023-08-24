#include <windows.h>
#include <iostream>
#include <string>
#include <tlhelp32.h>
#include <unordered_map>
// Function prototypes
void KillProcessById(DWORD processId);
DWORD GetProcessIdMakingMostModifications();

int main()
{
    // Set the directory to monitor
    std::wstring directoryToMonitor = L"C:\\Users\\JoãoBessa\\Downloads";

    // Create a buffer to store the file notification information
    const DWORD BufferSize = 64 * 1024;
    BYTE buffer[BufferSize];

    // Create an event to signal when a change occurs
    HANDLE changeEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    // Create a handle to the directory to monitor
    HANDLE directoryHandle = CreateFile(
        directoryToMonitor.c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
        NULL);

    // Check if the handle is valid
    if (directoryHandle == INVALID_HANDLE_VALUE)
    {
        std::cerr << "Error: Unable to open directory for monitoring." << std::endl;
        return -1;
    }

    // Create an overlapped structure for asynchronous operations
    OVERLAPPED overlapped = { 0 };
    overlapped.hEvent = changeEvent;

    // Start monitoring the directory for changes
    while (true)
    {
        // Reset the change event
        ResetEvent(changeEvent);

        // Request notifications for changes to the directory
        DWORD bytesReturned = 0;
        if (!ReadDirectoryChangesW(
            directoryHandle,
            buffer,
            BufferSize,
            TRUE,
            FILE_NOTIFY_CHANGE_FILE_NAME |
            FILE_NOTIFY_CHANGE_DIR_NAME |
            FILE_NOTIFY_CHANGE_ATTRIBUTES |
            FILE_NOTIFY_CHANGE_SIZE |
            FILE_NOTIFY_CHANGE_LAST_WRITE |
            FILE_NOTIFY_CHANGE_LAST_ACCESS |
            FILE_NOTIFY_CHANGE_CREATION |
            FILE_NOTIFY_CHANGE_SECURITY,
            &bytesReturned,
            &overlapped,
            NULL))
        {
            std::cerr << "Error: Unable to read directory changes." << std::endl;
            return -1;
        }

        // Wait for a change to occur
        if (WaitForSingleObject(changeEvent, INFINITE) == WAIT_OBJECT_0)
        {
            // Process the change notifications
            BYTE* p = buffer;
            while (p < buffer + bytesReturned)
            {
                // Get the file notification information
                FILE_NOTIFY_INFORMATION* info = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(p);
                p += info->NextEntryOffset;

                // Check if the file was modified
                if (info->Action == FILE_ACTION_MODIFIED)
                {
                    // Get the file name
                    std::wstring fileName(info->FileName, info->FileNameLength / sizeof(wchar_t));

                    // Check if the file extension was changed to a common ransomware extension
                    if (fileName.find(L".encrypted") != std::wstring::npos ||
                        fileName.find(L".locky") != std::wstring::npos ||
                        fileName.find(L".wannacry") != std::wstring::npos)
                    {
                        std::wcout << "Perigo! Temos um ransomware no pc que esta criptografando o arquivo: " << fileName << std::endl;

                        // Attempt to kill the ransomware process by analyzing its behavior
                        DWORD processId = GetProcessIdMakingMostModifications();
                        if (processId != 0)
                        {
                            KillProcessById(processId);
                        }
                    }
                }

                if (info->NextEntryOffset == 0)
                    break;
            }
        }
    }

    return 0;
}

// Function to kill a process by id
void KillProcessById(DWORD processId)
{
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0, processId);
    if (hProcess != NULL)
    {
        TerminateProcess(hProcess, 9);
        CloseHandle(hProcess);
        std::cout << "Ransomware process terminated: " << processId << std::endl;
    }
}

// Function to get the id of the process making the most file system modifications in a short period of time
DWORD GetProcessIdMakingMostModifications()
{
    const int NumSamples = 5;
    const int SampleIntervalMs = 100;

    // Create a map to store the number of file system modifications made by each process
    std::unordered_map<DWORD, int> processModifications;

    // Take multiple samples of the file system activity
    for (int i = 0; i < NumSamples; i++)
    {
        // Create a snapshot of the system processes
        HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapShot == INVALID_HANDLE_VALUE)
            return 0;

        // Iterate over the processes in the snapshot
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapShot, &pe))
        {
            do
            {
                // Open the process
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
                if (hProcess != NULL)
                {
                    // Get the IO counters for the process
                    IO_COUNTERS ioCounters;
                    if (GetProcessIoCounters(hProcess, &ioCounters))
                    {
                        // Increment the number of file system modifications made by this process
                        processModifications[pe.th32ProcessID] += ioCounters.WriteOperationCount;
                    }

                    CloseHandle(hProcess);
                }
            } while (Process32Next(hSnapShot, &pe));
        }

        CloseHandle(hSnapShot);

        // Sleep for a short period of time before taking the next sample
        Sleep(SampleIntervalMs);
    }

    // Find the process that made the most file system modifications
    DWORD maxProcessId = 0;
    int maxModifications = 0;
    for (const auto& entry : processModifications)
    {
        if (entry.second > maxModifications)
        {
            maxProcessId = entry.first;
            maxModifications = entry.second;
        }
    }

    return maxProcessId;
}
