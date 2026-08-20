// protocol.cpp — 头部编解码实现
#include "pch.h"
#include "protocol.h"

#include <cstring>
#include <string>

namespace c2
{

    void encode_header(const Header &h, uint8_t out[20])
    {
        std::memset(out, 0, kHeaderSize);
        // 强制写入 magic/version
        Header hh = h;
        hh.magic = kMagic;
        hh.version = kVersion;
        out[0] = (uint8_t)(hh.magic & 0xFF);
        out[1] = (uint8_t)(hh.magic >> 8);
        out[2] = hh.version;
        out[3] = hh.flags;
        out[4] = (uint8_t)(hh.seq & 0xFF);
        out[5] = (uint8_t)((hh.seq >> 8) & 0xFF);
        out[6] = (uint8_t)((hh.seq >> 16) & 0xFF);
        out[7] = (uint8_t)((hh.seq >> 24) & 0xFF);
        out[8] = (uint8_t)(hh.timestamp & 0xFF);
        out[9] = (uint8_t)((hh.timestamp >> 8) & 0xFF);
        out[10] = (uint8_t)((hh.timestamp >> 16) & 0xFF);
        out[11] = (uint8_t)((hh.timestamp >> 24) & 0xFF);
        out[12] = (uint8_t)(hh.cmd & 0xFF);
        out[13] = (uint8_t)(hh.cmd >> 8);
        out[14] = hh.plugin;
        out[15] = hh.status;
        out[16] = (uint8_t)(hh.payload_len & 0xFF);
        out[17] = (uint8_t)((hh.payload_len >> 8) & 0xFF);
        out[18] = (uint8_t)((hh.payload_len >> 16) & 0xFF);
        out[19] = (uint8_t)((hh.payload_len >> 24) & 0xFF);
    }

    bool decode_header(const uint8_t in[20], Header &h, std::string &err)
    {
        h.magic = (uint16_t)in[0] | ((uint16_t)in[1] << 8);
        h.version = in[2];
        h.flags = in[3];
        h.seq = (uint32_t)in[4] | ((uint32_t)in[5] << 8) | ((uint32_t)in[6] << 16) | ((uint32_t)in[7] << 24);
        h.timestamp = (uint32_t)in[8] | ((uint32_t)in[9] << 8) | ((uint32_t)in[10] << 16) | ((uint32_t)in[11] << 24);
        h.cmd = (uint16_t)in[12] | ((uint16_t)in[13] << 8);
        h.plugin = in[14];
        h.status = in[15];
        h.payload_len = (uint32_t)in[16] | ((uint32_t)in[17] << 8) | ((uint32_t)in[18] << 16) | ((uint32_t)in[19] << 24);

        if (h.magic != kMagic)
        {
            err = "bad magic";
            return false;
        }
        if (h.version != kVersion)
        {
            err = "bad version";
            return false;
        }
        if (h.payload_len > kMaxPayload)
        {
            err = "payload too large";
            return false;
        }
        return true;
    }

} // namespace c2
