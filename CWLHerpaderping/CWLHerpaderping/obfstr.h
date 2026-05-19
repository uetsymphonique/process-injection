#pragma once
#include <Windows.h>

// Compile-time XOR obfuscation for narrow strings (char*)
// Strings are encrypted at compile time with XOR key and decrypted on stack at runtime
// No plaintext API names or DLL names visible in .rdata section

template<size_t N, BYTE KEY = 0x5A>
class ObfStr {
private:
    char encrypted[N];

public:
    // Compile-time encryption
    constexpr ObfStr(const char(&str)[N]) : encrypted{} {
        for (size_t i = 0; i < N; i++) {
            encrypted[i] = str[i] ^ KEY;
        }
    }

    // Runtime decryption to stack buffer
    void decrypt(char* buffer) const {
        for (size_t i = 0; i < N; i++) {
            buffer[i] = encrypted[i] ^ KEY;
        }
    }

    // Helper: decrypt and return stack pointer
    char* get() const {
        static thread_local char buffer[N];
        decrypt(buffer);
        return buffer;
    }
};

// Compile-time XOR obfuscation for wide strings (wchar_t*)
template<size_t N, BYTE KEY = 0x5A>
class ObfWStr {
private:
    wchar_t encrypted[N];

public:
    constexpr ObfWStr(const wchar_t(&str)[N]) : encrypted{} {
        for (size_t i = 0; i < N; i++) {
            encrypted[i] = str[i] ^ KEY;
        }
    }

    void decrypt(wchar_t* buffer) const {
        for (size_t i = 0; i < N; i++) {
            buffer[i] = encrypted[i] ^ KEY;
        }
    }

    wchar_t* get() const {
        static thread_local wchar_t buffer[N];
        decrypt(buffer);
        return buffer;
    }
};

// Helper functions for template deduction
template<size_t N>
inline char* MakeObfStr(const char(&s)[N]) {
    static ObfStr<N> obf(s);
    return obf.get();
}

template<size_t N>
inline wchar_t* MakeObfWStr(const wchar_t(&s)[N]) {
    static ObfWStr<N> obf(s);
    return obf.get();
}

// Macros for easy usage
#define OBFSTR(s) MakeObfStr(s)
#define OBFWSTR(s) MakeObfWStr(s)
