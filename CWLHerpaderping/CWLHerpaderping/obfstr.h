#pragma once
#include <Windows.h>

// Compile-time XOR obfuscation for narrow strings (char*)
// Strings are encrypted at compile time with XOR key and decrypted on stack at runtime
// No plaintext API names or DLL names visible in .rdata section

template<size_t N>
class ObfStr {
private:
    char encrypted[N];

    static constexpr BYTE _key(size_t i) {
        return (BYTE)((0xA3 + i * 0x5B) & 0xFF);
    }

public:
    constexpr ObfStr(const char(&str)[N]) : encrypted{} {
        for (size_t i = 0; i < N; i++) {
            encrypted[i] = str[i] ^ _key(i);
        }
    }

    void decrypt(char* buffer) const {
        for (size_t i = 0; i < N; i++) {
            buffer[i] = encrypted[i] ^ _key(i);
        }
    }

    char* get() const {
        static thread_local char buffer[N];
        decrypt(buffer);
        return buffer;
    }
};

// Compile-time XOR obfuscation for wide strings (wchar_t*)
template<size_t N>
class ObfWStr {
private:
    wchar_t encrypted[N];

    static constexpr BYTE _key(size_t i) {
        return (BYTE)((0xA3 + i * 0x5B) & 0xFF);
    }

public:
    constexpr ObfWStr(const wchar_t(&str)[N]) : encrypted{} {
        for (size_t i = 0; i < N; i++) {
            encrypted[i] = str[i] ^ (wchar_t)_key(i);
        }
    }

    void decrypt(wchar_t* buffer) const {
        for (size_t i = 0; i < N; i++) {
            buffer[i] = encrypted[i] ^ (wchar_t)_key(i);
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
