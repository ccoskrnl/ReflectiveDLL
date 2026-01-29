#include "pch.h"
#include "net.h"
#include "mylibc.h"

#include "types.h"



status_t startup_wsa(winsock_functions_t* ws2)
{
	WSADATA wsa_data;
	int result = 1;
	if ((result = ws2->WSAStartup(MAKEWORD(2, 2), &wsa_data)) != 0)
	{
		return ST_ERROR;
	}

	return ST_SUCCESS;
}

void cleanup_wsa(winsock_functions_t* ws2)
{
	ws2->WSACleanup();
}

void close_socket(SOCKET socket, winsock_functions_t* ws2)
{
	ws2->CloseSocket(socket);
}

SOCKET init_connection(const char* hostname, int port, winsock_functions_t* ws2)
{
	SOCKET server_socket = INVALID_SOCKET;
	struct sockaddr_in server_addr = { 0 };


	while(1)
	{
		server_socket = ws2->WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
		if (server_socket == INVALID_SOCKET)
		{
			return INVALID_SOCKET;
		}

		server_addr.sin_family = AF_INET;
		server_addr.sin_port = ws2->Htons(port);
		if (ws2->Inet_pton(AF_INET, hostname, &server_addr.sin_addr) <= 0)
		{
			return INVALID_SOCKET;
		}

		if (ws2->WSAConnect(server_socket, (SOCKADDR*)&server_addr, sizeof(server_addr), NULL, NULL, NULL, NULL) == SOCKET_ERROR)
		{
			ws2->CloseSocket(server_socket);
			Sleep(5000);
			continue;
		}
		break;
	}

	return server_socket;

}

status_t send_data(SOCKET socket, char* buf, SIZE_T size, DWORD* bytes_sent, winsock_functions_t* ws2)
{
	status_t status = ST_SUCCESS;
	WSABUF wsabuf = { 0 };
	wsabuf.buf = buf;
	wsabuf.len = size;
	while (1)
	{
		status = ws2->WSASend(socket, &wsabuf, 1, bytes_sent, 0, NULL, NULL);
		if (status == SOCKET_ERROR)
		{
			int error = ws2->WSAGetLastError();

			if (error == WSAEWOULDBLOCK)
			{
				Sleep(10);
				continue;
			}

			return ST_SOCKET_ERROR;
		}
		else if (status == 0)
		{
			return ST_SOCKET_ERROR;
		}
		break;

	}
	
	return status;

}

status_t send_file(SOCKET socket, const char* filepath, winsock_functions_t* ws2)
{
	if (ws2 == NULL)
		return ST_ERROR;

	HANDLE hFile = INVALID_HANDLE_VALUE;
	status_t status = ST_SUCCESS;
	int send_result = 0;

	const DWORD BUFFER_SIZE = 64 * 1024;
	BYTE* buffer = NULL;

	DWORD error = 0;

	hFile = CreateFileA(
		filepath,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
		NULL
	);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		return ST_ERROR;

	}

	LARGE_INTEGER file_size = { 0 };
	DWORD file_size_low;
	file_size_low = GetFileSize(hFile, NULL);
	if (file_size_low == INVALID_FILE_SIZE)
	{
		CloseHandle(hFile);
		return ST_ERROR;
	}
	file_size.QuadPart = file_size_low;
	UINT64 size_be = my_byteswap_uint64(file_size.QuadPart);
	DWORD size_data_sent = 0;

	if (send_data(socket, (char*)&size_be, sizeof(UINT64), &size_data_sent, ws2) != 0)
	{
		CloseHandle(hFile);
		return ST_SOCKET_ERROR;
	}


	buffer = (BYTE*)my_malloc(BUFFER_SIZE);
	if (buffer == NULL)
	{
		CloseHandle(hFile);
		return ST_MEM_ALLOC_ERROR;
	}

	// set 30s timeout
	//int send_timeout = 30000;
	//ws->setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, (const char*)&send_timeout, sizeof(send_timeout));

	DWORD bytes_read = 0;
	BOOL read_result = TRUE;
	LONGLONG total_sent = 0;

	while (total_sent < file_size.QuadPart)
	{
		// read file data into buffer, the var bytes_read records how bytes we read this time.
		read_result = ReadFile(hFile, buffer, BUFFER_SIZE, &bytes_read, NULL);
		if (!read_result || bytes_read == 0)
		{

			DWORD error = GetLastError();
			if (error != ERROR_SUCCESS && error != ERROR_HANDLE_EOF)
			{
				status = ST_ERROR;
				break;
			}

			if (bytes_read == 0)
				break;
		}


		// how bytes we need to send
		DWORD bytes_need_to_send = bytes_read;
		// bytes we have sent.
		DWORD bytes_sent = 0;

		while (bytes_sent < bytes_need_to_send)
		{

			send_result = send_data(socket, (char*)(buffer + bytes_sent), bytes_need_to_send, &bytes_sent, ws2);
			if (send_result == SOCKET_ERROR)
			{
				int error = ws2->WSAGetLastError();

				if (error == WSAEWOULDBLOCK)
				{
					Sleep(10);
					continue;
				}

				status = ST_SOCKET_ERROR;
				goto cleanup;
			}
			else if (send_result == 0)
			{
				status = ST_SOCKET_ERROR;
				goto cleanup;
			}

			total_sent += bytes_sent;
		}

	}

	if (total_sent == file_size.QuadPart)
	{
		status = 0;
	}

cleanup:

	if (buffer)
	{
		my_free(buffer);
	}

	if (hFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFile);
	}

__exit:
	return status;
}

status_t recv_data(SOCKET socket, char* buf, int len, DWORD* total_received, winsock_functions_t* ws2)
{
	if (ws2 == NULL)
	{
		return FALSE;
	}

	DWORD flags = 0;
	status_t status = ST_SUCCESS;

	WSABUF wsabuf = { 0 };
	wsabuf.buf = buf;
	wsabuf.len = len;
	
	status = ws2->WSARecv(socket, &wsabuf, 1, total_received, &flags, NULL, NULL);
	if (status == SOCKET_ERROR)
	{
		int error = ws2->WSAGetLastError();
		return ST_SOCKET_ERROR;
	}
	else if (status == 0)
	{
		return ST_SOCKET_ERROR;
	}
	
	return ST_SUCCESS;
}


