#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace abse_zkp {

struct EnclaveFilePacket {
    std::string name;
    std::vector<unsigned char> content;
};

std::vector<unsigned char> ReadBinaryFile(const std::filesystem::path& path);
bool WriteBinaryFile(const std::filesystem::path& path, const std::vector<unsigned char>& bytes);
std::filesystem::path MakeUniqueTempDir(const std::string& prefix);
bool SendFilePacket(int fd, const std::vector<EnclaveFilePacket>& files);
bool ReceiveFilePacket(int fd, std::vector<EnclaveFilePacket>& files);
int ConnectVsock(std::uint32_t enclave_cid, std::uint32_t port, int timeout_ms);
int ListenVsock(std::uint32_t port);
int AcceptVsock(int listen_fd, int timeout_ms);
void ConfigureSocketTimeouts(int fd, int timeout_ms);
void CloseSocket(int fd);

}  // namespace abse_zkp
