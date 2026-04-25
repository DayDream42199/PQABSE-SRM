#include "system/NitroEnclaveProtocol.h"

#include <chrono>
#include <fstream>
#include <random>
#include <stdexcept>

#ifdef __linux__
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/vm_sockets.h>
#include <unistd.h>
#endif

namespace abse_zkp {
namespace {

bool SendAll(int fd, const void* buffer, std::size_t size) {
    const auto* current = static_cast<const unsigned char*>(buffer);
    std::size_t remaining = size;
    while (remaining > 0) {
#ifdef __linux__
        const auto sent = ::send(fd, current, remaining, 0);
#else
        const auto sent = -1;
#endif
        if (sent <= 0) {
            return false;
        }
        current += static_cast<std::size_t>(sent);
        remaining -= static_cast<std::size_t>(sent);
    }
    return true;
}

bool RecvAll(int fd, void* buffer, std::size_t size) {
    auto* current = static_cast<unsigned char*>(buffer);
    std::size_t remaining = size;
    while (remaining > 0) {
#ifdef __linux__
        const auto received = ::recv(fd, current, remaining, 0);
#else
        const auto received = -1;
#endif
        if (received <= 0) {
            return false;
        }
        current += static_cast<std::size_t>(received);
        remaining -= static_cast<std::size_t>(received);
    }
    return true;
}

timeval ToTimeval(int timeout_ms) {
    timeval value{};
    value.tv_sec = timeout_ms / 1000;
    value.tv_usec = static_cast<suseconds_t>((timeout_ms % 1000) * 1000);
    return value;
}

}  // namespace

std::vector<unsigned char> ReadBinaryFile(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input.is_open()) {
        throw std::runtime_error("Failed to open file for reading: " + path.string());
    }
    return std::vector<unsigned char>(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

bool WriteBinaryFile(const std::filesystem::path& path, const std::vector<unsigned char>& bytes) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output.is_open()) {
        return false;
    }
    output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    return static_cast<bool>(output);
}

std::filesystem::path MakeUniqueTempDir(const std::string& prefix) {
    std::mt19937_64 rng(static_cast<std::mt19937_64::result_type>(
        std::chrono::high_resolution_clock::now().time_since_epoch().count()));
    for (int attempt = 0; attempt < 16; ++attempt) {
        const auto candidate = std::filesystem::temp_directory_path() /
                               (prefix + "_" + std::to_string(static_cast<unsigned long long>(rng())));
        std::error_code ec;
        if (std::filesystem::create_directories(candidate, ec) && !ec) {
            return candidate;
        }
    }
    throw std::runtime_error("Failed to create unique temp directory for Nitro enclave exchange");
}

bool SendFilePacket(int fd, const std::vector<EnclaveFilePacket>& files) {
    const std::uint32_t file_count = static_cast<std::uint32_t>(files.size());
    if (!SendAll(fd, &file_count, sizeof(file_count))) {
        return false;
    }
    for (const auto& file : files) {
        const std::uint32_t name_size = static_cast<std::uint32_t>(file.name.size());
        const std::uint64_t data_size = static_cast<std::uint64_t>(file.content.size());
        if (!SendAll(fd, &name_size, sizeof(name_size)) ||
            !SendAll(fd, file.name.data(), file.name.size()) ||
            !SendAll(fd, &data_size, sizeof(data_size)) ||
            !SendAll(fd, file.content.data(), file.content.size())) {
            return false;
        }
    }
    return true;
}

bool ReceiveFilePacket(int fd, std::vector<EnclaveFilePacket>& files) {
    std::uint32_t file_count = 0;
    if (!RecvAll(fd, &file_count, sizeof(file_count))) {
        return false;
    }
    files.clear();
    files.reserve(file_count);
    for (std::uint32_t i = 0; i < file_count; ++i) {
        std::uint32_t name_size = 0;
        std::uint64_t data_size = 0;
        if (!RecvAll(fd, &name_size, sizeof(name_size))) {
            return false;
        }
        std::string name(name_size, '\0');
        if (!RecvAll(fd, name.data(), name.size()) || !RecvAll(fd, &data_size, sizeof(data_size))) {
            return false;
        }
        std::vector<unsigned char> bytes(static_cast<std::size_t>(data_size));
        if (!RecvAll(fd, bytes.data(), bytes.size())) {
            return false;
        }
        files.push_back({std::move(name), std::move(bytes)});
    }
    return true;
}

void ConfigureSocketTimeouts(int fd, int timeout_ms) {
#ifdef __linux__
    const auto timeout = ToTimeval(timeout_ms);
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
#else
    (void)fd;
    (void)timeout_ms;
#endif
}

int ConnectVsock(std::uint32_t enclave_cid, std::uint32_t port, int timeout_ms) {
#ifndef __linux__
    (void)enclave_cid;
    (void)port;
    (void)timeout_ms;
    throw std::runtime_error("Nitro Enclave vsock transport is supported only on Linux");
#else
    const int fd = ::socket(AF_VSOCK, SOCK_STREAM, 0);
    if (fd < 0) {
        throw std::runtime_error("Failed to create vsock client socket");
    }
    ConfigureSocketTimeouts(fd, timeout_ms);
    sockaddr_vm address{};
    address.svm_family = AF_VSOCK;
    address.svm_cid = enclave_cid;
    address.svm_port = port;
    if (::connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
        ::close(fd);
        throw std::runtime_error("Failed to connect to Nitro enclave over vsock");
    }
    return fd;
#endif
}

int ListenVsock(std::uint32_t port) {
#ifndef __linux__
    (void)port;
    throw std::runtime_error("Nitro Enclave vsock listener is supported only on Linux");
#else
    const int fd = ::socket(AF_VSOCK, SOCK_STREAM, 0);
    if (fd < 0) {
        throw std::runtime_error("Failed to create vsock server socket");
    }
    sockaddr_vm address{};
    address.svm_family = AF_VSOCK;
    address.svm_cid = VMADDR_CID_ANY;
    address.svm_port = port;
    if (::bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 ||
        ::listen(fd, 8) != 0) {
        ::close(fd);
        throw std::runtime_error("Failed to bind/listen on Nitro enclave vsock port");
    }
    return fd;
#endif
}

int AcceptVsock(int listen_fd, int timeout_ms) {
#ifndef __linux__
    (void)listen_fd;
    (void)timeout_ms;
    throw std::runtime_error("Nitro Enclave vsock accept is supported only on Linux");
#else
    ConfigureSocketTimeouts(listen_fd, timeout_ms);
    const int fd = ::accept(listen_fd, nullptr, nullptr);
    if (fd < 0) {
        throw std::runtime_error("Failed to accept Nitro enclave vsock client");
    }
    ConfigureSocketTimeouts(fd, timeout_ms);
    return fd;
#endif
}

void CloseSocket(int fd) {
#ifdef __linux__
    if (fd >= 0) {
        ::close(fd);
    }
#else
    (void)fd;
#endif
}

}  // namespace abse_zkp
