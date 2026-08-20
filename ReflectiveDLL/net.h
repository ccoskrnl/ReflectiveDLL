// net.h — Winsock 封装：连接 + 完整收发 + 协议包读写
#pragma once

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <winsock2.h>

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

#include "protocol.h"

namespace c2
{

    // 进程级初始化/清理（引用计数）
    bool net_init();
    void net_cleanup();

    // 连接 host:port（timeout_ms<0 阻塞）；成功返回 true 并置 out
    bool net_connect(const std::string &host, uint16_t port, SOCKET *out,
                     int timeout_ms = 5000);
    void net_close(SOCKET s);

    // 完整收发
    bool net_send_all(SOCKET s, const void *buf, size_t len);
    bool net_recv_all(SOCKET s, void *buf, size_t len, int timeout_ms = -1);

    // 协议包读写（20B 头 + payload；payload 未解密）
    bool net_read_packet(SOCKET s, Header &h, std::vector<uint8_t> &payload,
                         int timeout_ms = -1);
    bool net_write_packet(SOCKET s, const Header &h, const void *payload,
                          size_t len);

    std::string net_last_error();

} // namespace c2
