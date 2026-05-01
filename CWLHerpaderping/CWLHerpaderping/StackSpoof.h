#pragma once
#include <Windows.h>
#include <Psapi.h>

// Find a legitimate return address gadget in a trusted module
PVOID FindReturnAddressGadget(const char* moduleName);

// Spoof call stack wrapper for NT API calls
// This class manages stack frame manipulation
class StackSpoofer {
private:
    PVOID originalReturnAddress;
    PVOID* returnAddressLocation;
    PVOID fakeReturnAddress;
    BOOL isActive;

public:
    StackSpoofer(const char* trustedModule = "kernel32.dll");
    ~StackSpoofer();
    
    // Activate spoofing (call before sensitive API)
    void Activate();
    
    // Deactivate spoofing (call after sensitive API)
    void Deactivate();
};

// Helper macro for easy spoofing
#define SPOOF_CALL(trustedModule, apiCall) \
    do { \
        StackSpoofer spoofer(trustedModule); \
        spoofer.Activate(); \
        apiCall; \
        spoofer.Deactivate(); \
    } while(0)
