// crypto_utils.hpp
// Password hashing (SHA-256 + per-user salt) and a lightweight signed-token
// scheme (HMAC-SHA256), used in place of a hosted auth provider like Clerk.
#pragma once

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <random>

namespace crypto_utils {

inline std::string toHex(const unsigned char* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    return oss.str();
}

inline std::string sha256Hex(const std::string& input) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, input.c_str(), input.size());
    EVP_DigestFinal_ex(ctx, hash, &hashLen);
    EVP_MD_CTX_free(ctx);
    return toHex(hash, hashLen);
}

inline std::string generateSalt(size_t numBytes = 16) {
    std::vector<unsigned char> buf(numBytes);
    RAND_bytes(buf.data(), (int)numBytes);
    return toHex(buf.data(), numBytes);
}

// Hash a plaintext password with a salt. Store both salt and hash in DB.
inline std::string hashPassword(const std::string& password, const std::string& salt) {
    return sha256Hex(salt + ":" + password);
}

inline bool verifyPassword(const std::string& password, const std::string& salt,
                            const std::string& storedHash) {
    return hashPassword(password, salt) == storedHash;
}

// --- Lightweight signed session tokens (HMAC-SHA256) ---
// Format: base64url(payload_json) + "." + hex(HMAC(payload_json, secret))
// This mimics what a hosted auth provider (Clerk, Auth0) issues, without
// needing an external account. Swap this module out for a real provider's
// SDK verification call if/when you connect one.

inline std::string hmacHex(const std::string& data, const std::string& secret) {
    unsigned char* result;
    unsigned int len = 0;
    result = HMAC(EVP_sha256(), secret.c_str(), (int)secret.size(),
                  (const unsigned char*)data.c_str(), data.size(), nullptr, &len);
    return toHex(result, len);
}

// Base64url encode (no padding) - matches the JWT convention so header
// values stay free of quotes/braces/slashes.
inline std::string base64UrlEncode(const std::string& input) {
    static const std::string chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int val = 0, valb = -6;
    for (unsigned char c : input) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) out.push_back(chars[((val << 8) >> (valb + 8)) & 0x3F]);
    // make URL-safe and strip padding needs
    for (auto& c : out) {
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
    }
    return out;
}

// Minimal standard base64 decoder (input from a JSON body, e.g. file uploads).
inline std::string base64Decode(const std::string& input) {
    static const std::string chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    auto isBase64Char = [](unsigned char c) {
        return (isalnum(c) || c == '+' || c == '/');
    };
    int inLen = (int)input.size();
    int i = 0, j = 0, in_ = 0;
    unsigned char charArray4[4], charArray3[3];
    std::string ret;

    while (inLen-- && (input[in_] != '=') && isBase64Char(input[in_])) {
        charArray4[i++] = input[in_]; in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++) charArray4[i] = (unsigned char)chars.find(charArray4[i]);
            charArray3[0] = (charArray4[0] << 2) + ((charArray4[1] & 0x30) >> 4);
            charArray3[1] = ((charArray4[1] & 0xf) << 4) + ((charArray4[2] & 0x3c) >> 2);
            charArray3[2] = ((charArray4[2] & 0x3) << 6) + charArray4[3];
            for (i = 0; i < 3; i++) ret += charArray3[i];
            i = 0;
        }
    }
    if (i) {
        for (j = i; j < 4; j++) charArray4[j] = 0;
        for (j = 0; j < 4; j++) charArray4[j] = (unsigned char)chars.find(charArray4[j]);
        charArray3[0] = (charArray4[0] << 2) + ((charArray4[1] & 0x30) >> 4);
        charArray3[1] = ((charArray4[1] & 0xf) << 4) + ((charArray4[2] & 0x3c) >> 2);
        charArray3[2] = ((charArray4[2] & 0x3) << 6) + charArray4[3];
        for (j = 0; j < i - 1; j++) ret += charArray3[j];
    }
    return ret;
}

inline std::string base64UrlDecode(const std::string& input) {
    std::string s = input;
    for (auto& c : s) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }
    while (s.size() % 4 != 0) s.push_back('=');
    return base64Decode(s); // defined below
}

inline std::string signToken(const std::string& payloadJson, const std::string& secret) {
    std::string encodedPayload = base64UrlEncode(payloadJson);
    std::string sig = hmacHex(encodedPayload, secret);
    return encodedPayload + "." + sig;
}

// Returns the payload JSON string if signature is valid, empty string otherwise.
inline std::string verifyToken(const std::string& token, const std::string& secret) {
    auto pos = token.rfind('.');
    if (pos == std::string::npos) return "";
    std::string encodedPayload = token.substr(0, pos);
    std::string sig = token.substr(pos + 1);
    std::string expected = hmacHex(encodedPayload, secret);
    if (sig.size() != expected.size()) return "";
    // constant-time-ish compare
    unsigned char diff = 0;
    for (size_t i = 0; i < sig.size(); ++i) diff |= (sig[i] ^ expected[i]);
    if (diff != 0) return "";
    return base64UrlDecode(encodedPayload);
}

inline long long nowEpochSeconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

inline std::string randomToken(size_t numBytes = 24) {
    std::vector<unsigned char> buf(numBytes);
    RAND_bytes(buf.data(), (int)numBytes);
    return toHex(buf.data(), numBytes);
}

} // namespace crypto_utils
