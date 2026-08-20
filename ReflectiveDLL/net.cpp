// net.cpp — Winsock 封装实现
#include "pch.h"
#include "net.h"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <ws2tcpip.h>

namespace c2
{

    namespace
    {

        std::atomic<int> g_refs{0};
        std::mutex g_mutex;

        std::string ws_err(int e)
        {
            char buf[256] = {0};
            FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                           nullptr, (DWORD)e, 0, buf, sizeof(buf), nullptr);
            std::string s(buf);
            while (!s.empty() && (s.back() == '\r' || s.back() == '\n' || s.back() == ' '))
                s.pop_back();
            return s;
        }

    } // namespace

    bool net_init()
    {
        std::lock_guard<std::mutex> lk(g_mutex);
        if (g_refs.fetch_add(1) > 0)
            return true;
        WSADATA wd{};
        if (WSAStartup(MAKEWORD(2, 2), &wd) != 0)
        {
            g_refs.fetch_sub(1);
            return false;
        }
        return true;
    }

    void net_cleanup()
    {
        std::lock_guard<std::mutex> lk(g_mutex);
        if (g_refs.fetch_sub(1) == 1)
            WSACleanup();
    }

    std::string net_last_error()
    {
        return ws_err(WSAGetLastError());
    }

    bool net_connect(const std::string &host, uint16_t port, SOCKET *out,
                     int timeout_ms)
    {
        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        addrinfo *res = nullptr;
        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);
        if (getaddrinfo(host.c_str(), port_str, &hints, &res) != 0)
            return false;

        SOCKET s = INVALID_SOCKET;
        for (addrinfo *ai = res; ai; ai = ai->ai_next)
        {
            s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
            if (s == INVALID_SOCKET)
                continue;
            if (timeout_ms < 0)
            {
                if (connect(s, ai->ai_addr, (int)ai->ai_addrlen) == 0)
                    break;
            }
            else
            {
                u_long mode = 1;
                ioctlsocket(s, FIONBIO, &mode);
                int rc = connect(s, ai->ai_addr, (int)ai->ai_addrlen);
                if (rc == 0)
                {
                    mode = 0;
                    ioctlsocket(s, FIONBIO, &mode);
                    break;
                }
                if (WSAGetLastError() == WSAEWOULDBLOCK)
                {
                    fd_set wf;
                    FD_ZERO(&wf);
                    FD_SET(s, &wf);
                    timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
                    rc = select(0, nullptr, &wf, nullptr, &tv);
                    if (rc == 1)
                    {
                        int so_err = 0;
                        int len = sizeof(so_err);
                        getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&so_err, &len);
                        if (so_err == 0)
                        {
                            mode = 0;
                            ioctlsocket(s, FIONBIO, &mode);
                            break;
                        }
                    }
                }
            }
            closesocket(s);
            s = INVALID_SOCKET;
        }
        freeaddrinfo(res);
        if (s == INVALID_SOCKET)
            return false;
        *out = s;
        return true;
    }

    void net_close(SOCKET s)
    {
        if (s != INVALID_SOCKET)
            closesocket(s);
    }

    bool net_send_all(SOCKET s, const void *buf, size_t len)
    {
        const char *p = (const char *)buf;
        size_t sent = 0;
        while (sent < len)
        {
            int n = send(s, p + sent, (int)(len - sent), 0);
            if (n == SOCKET_ERROR)
                return false;
            sent += (size_t)n;
        }
        return true;
    }

    bool net_recv_all(SOCKET s, void *buf, size_t len, int timeout_ms)
    {
        char *p = (char *)buf;
        size_t got = 0;
        while (got < len)
        {
            if (timeout_ms >= 0)
            {
                fd_set rf;
                FD_ZERO(&rf);
                FD_SET(s, &rf);
                timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
                int rc = select(0, &rf, nullptr, nullptr, &tv);
                if (rc <= 0)
                    return false;
            }
            int n = recv(s, p + got, (int)(len - got), 0);
            if (n <= 0)
                return false;
            got += (size_t)n;
        }
        return true;
    }

    bool net_read_packet(SOCKET s, Header &h, std::vector<uint8_t> &payload,
                         int timeout_ms)
    {
        uint8_t hdr[kHeaderSize];
        if (!net_recv_all(s, hdr, kHeaderSize, timeout_ms))
            return false;
        std::string err;
        if (!decode_header(hdr, h, err))
            return false;
        payload.resize(h.payload_len);
        if (h.payload_len > 0 && !net_recv_all(s, payload.data(), h.payload_len, timeout_ms))
            return false;
        return true;
    }

    bool net_write_packet(SOCKET s, const Header &h, const void *payload,
                          size_t len)
    {
        if (len > kMaxPayload)
            return false;
        Header hh = h;
        hh.payload_len = (uint32_t)len;
        uint8_t hdr[kHeaderSize];
        encode_header(hh, hdr);
        // 头 + 载荷合并为一次 send：避免 Nagle 对小包的延迟（TCP 是字节流，
        // 接收端按长度分帧，合并与否不影响正确性）。M1 载荷都很小（握手/心跳
        // < 100B），多一次拷贝可接受；未来大载荷（如屏幕帧）可按需改回分次发送。
        std::vector<uint8_t> buf;
        buf.reserve(kHeaderSize + len);
        buf.insert(buf.end(), hdr, hdr + kHeaderSize);
        if (len > 0)
        {
            const uint8_t *p = static_cast<const uint8_t *>(payload);
            buf.insert(buf.end(), p, p + len);
        }
        return net_send_all(s, buf.data(), buf.size());
    }

} // namespace c2
