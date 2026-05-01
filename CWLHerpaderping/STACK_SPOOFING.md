# Call Stack Spoofing Enhancement for Herpaderping

## Overview

This enhancement adds **Call Stack Spoofing** to the Process Herpaderping technique to evade EDR stack walking detection. When EDRs like CrowdStrike analyze suspicious API calls, they examine the call stack to determine if the call originates from legitimate code. This implementation fakes legitimate return addresses to bypass such detection.

## How It Works

### The Problem

When malware directly calls sensitive NT APIs like `NtCreateSection`, `NtCreateProcessEx`, or `NtWriteVirtualMemory`, the call stack looks suspicious:

```
Stack Trace (SUSPICIOUS):
0: ntdll!NtCreateProcessEx
1: malware.exe!Herpaderping+0x234  ← EDR flags this!
2: malware.exe!main+0x42
3: ntdll!RtlUserThreadStart
```

### The Solution

Stack spoofing modifies the return address on the stack to point to legitimate code in trusted modules (e.g., `kernel32.dll`):

```
Stack Trace (APPEARS LEGITIMATE):
0: ntdll!NtCreateProcessEx
1: kernel32.dll!CreateProcessW+0x156  ← Looks like normal process creation!
2: kernel32.dll!BaseThreadInitThunk
3: ntdll!RtlUserThreadStart
```

## Implementation Details

### Core Components

**StackSpoof.h / StackSpoof.cpp**
- `FindReturnAddressGadget()`: Searches for RET instructions in legitimate modules
- `StackSpoofer` class: RAII wrapper that manages stack manipulation
  - `Activate()`: Replaces return address with fake one
  - `Deactivate()`: Restores original return address

### Integration Points

All sensitive NT API calls are wrapped with stack spoofing:

1. **NtCreateSection** - Creating memory section from temp file
2. **NtCreateProcessEx** - Creating ghost process from section
3. **NtAllocateVirtualMemory** - Allocating process parameters
4. **NtWriteVirtualMemory** - Writing to remote process
5. **NtCreateThreadEx** - Creating execution thread

### Usage Pattern

```cpp
// Before (suspicious)
status = pNtCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, ...);

// After (spoofed)
{
    StackSpoofer spoofer("kernel32.dll");
    spoofer.Activate();
    status = pNtCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, ...);
    spoofer.Deactivate();
}
```

The spoofing is automatic - the `StackSpoofer` destructor ensures cleanup even if exceptions occur.

## Technical Details

### Gadget Selection

The implementation searches for two types of gadgets in legitimate modules:

1. **Function Epilogue Pattern**: `add rsp, 0x28; ret` (0x48 0x83 0xC4 0x28 0xC3)
   - Most realistic as it mimics actual function returns
   
2. **Simple RET**: `ret` (0xC3)
   - Fallback if epilogue not found
   - Must be in executable memory region

### Memory Safety

- Uses RAII pattern via C++ class destructor
- Automatically restores stack on scope exit
- Safe even if API call throws exceptions

### Compatibility

- Works on x64 and x86 architectures
- Requires Psapi.lib for `GetModuleInformation()`
- Compatible with Windows 10/11

## Building

The project configuration has been updated to include:

- `StackSpoof.cpp` in compilation
- `StackSpoof.h` in headers
- `Psapi.lib` in linker dependencies (all configurations)

Build as usual:

```powershell
# Using MSBuild
msbuild CWLHerpaderping.sln /p:Configuration=Release /p:Platform=x64

# Using Visual Studio
# Just open and build normally
```

## Detection Evasion

### What This Bypasses

✅ **User-mode stack walking**: EDR sees legitimate return addresses  
✅ **Behavioral analysis**: Call chain appears normal  
✅ **Static analysis**: No suspicious import patterns  

### What This Doesn't Bypass

❌ **Kernel-mode callbacks**: Still visible at kernel level  
❌ **ETW events**: System events still logged  
❌ **Memory scanning**: Suspicious memory patterns remain  

### Recommended Combinations

For maximum evasion, combine with:

1. **Direct Syscalls**: Bypass user-mode hooks entirely
2. **ETW Patching**: Disable event logging
3. **Sleep Obfuscation**: Evade sandbox timeouts
4. **PPID Spoofing**: Fake legitimate parent process

## Debugging

The implementation includes verbose logging to track spoofing activity:

```
[+] Found gadget in kernel32.dll at: 0x00007FF8ABCD1234
[*] Calling NtCreateSection with spoofed stack...
[*] Stack spoofed: 0x000000ABCDEF0000 -> 0x00007FF8ABCD1234
[+] Section created from the temp file...
[*] Stack restored: 0x000000ABCDEF0000
```

To disable for production, comment out `wprintf()` calls in `StackSpoof.cpp`.

## References

- **Silent Moonwalk**: https://github.com/klezVirus/SilentMoonwalk
- **Call Stack Spoofing**: https://www.ired.team/offensive-security/defense-evasion/stack-spoofing
- **Threadless Injection**: https://github.com/CCob/ThreadlessInject

## Security Notice

This code is for educational and authorized security testing purposes only. Unauthorized use against systems you don't own or have permission to test is illegal.
