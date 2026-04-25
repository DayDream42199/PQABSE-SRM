#include "entities/NitroTeeClient.h"

#include <filesystem>
#include <stdexcept>

#include "system/NitroEnclaveProtocol.h"

namespace abse_zkp {
namespace {

std::string JoinStrings(const std::vector<std::string>& values) {
    std::string joined;
    for (std::size_t i = 0; i < values.size(); ++i) {
        if (i > 0) {
            joined.push_back(',');
        }
        joined += values[i];
    }
    return joined;
}

std::string BuildKeygenRequest(const std::string& gid,
                               const std::vector<std::string>& attributes,
                               int epoch,
                               const std::string& update_seed) {
    std::string content;
    content += "gid=" + gid + "\n";
    content += "attributes=" + JoinStrings(attributes) + "\n";
    content += "epoch=" + std::to_string(epoch) + "\n";
    content += "update_seed=" + update_seed + "\n";
    return content;
}

std::vector<unsigned char> ToBytes(const std::string& value) {
    return std::vector<unsigned char>(value.begin(), value.end());
}

std::vector<unsigned char> FindPacketContent(const std::vector<EnclaveFilePacket>& files, const std::string& name) {
    for (const auto& file : files) {
        if (file.name == name) {
            return file.content;
        }
    }
    return {};
}

std::string ReadStatus(const std::vector<EnclaveFilePacket>& files) {
    const auto bytes = FindPacketContent(files, "status.txt");
    return std::string(bytes.begin(), bytes.end());
}

}  // namespace

void NitroTeeClient::GenerateUserKey(const SystemParams& params,
                                     const PK& pk,
                                     const MSK& msk,
                                     const std::string& gid,
                                     const std::vector<std::string>& attributes,
                                     UserSecretKey& user_key,
                                     int epoch,
                                     const std::string& update_seed,
                                     const NitroTeeOptions& options) const {
    const auto temp_dir = MakeUniqueTempDir("pqabse_ta_nitro_parent");
    if (!SavePhase1Artifacts(params, pk, msk, temp_dir.string())) {
        std::error_code ignored;
        std::filesystem::remove_all(temp_dir, ignored);
        throw std::runtime_error("Failed to stage phase1 artifacts for Nitro enclave keygen");
    }

    std::vector<EnclaveFilePacket> request_files;
    request_files.push_back({"phase1_params.txt", ReadBinaryFile(temp_dir / "phase1_params.txt")});
    request_files.push_back({"phase1_public_key.bin", ReadBinaryFile(temp_dir / "phase1_public_key.bin")});
    request_files.push_back({"phase1_trapdoor.bin", ReadBinaryFile(temp_dir / "phase1_trapdoor.bin")});
    request_files.push_back({"keygen_request.txt", ToBytes(BuildKeygenRequest(gid, attributes, epoch, update_seed))});

    const int fd = ConnectVsock(options.enclave_cid, options.port, options.timeout_ms);
    try {
        if (!SendFilePacket(fd, request_files)) {
            throw std::runtime_error("Failed to send keygen request to Nitro enclave");
        }
        std::vector<EnclaveFilePacket> response_files;
        if (!ReceiveFilePacket(fd, response_files)) {
            throw std::runtime_error("Failed to receive keygen response from Nitro enclave");
        }
        const auto status = ReadStatus(response_files);
        if (status != "OK") {
            const auto error_bytes = FindPacketContent(response_files, "error.txt");
            throw std::runtime_error("Nitro enclave keygen failed: " +
                                     std::string(error_bytes.begin(), error_bytes.end()));
        }
        const auto user_key_bytes = FindPacketContent(response_files, "user_key.bin");
        if (user_key_bytes.empty()) {
            throw std::runtime_error("Nitro enclave keygen response missing user_key.bin");
        }
        const auto user_key_path = temp_dir / "user_key.bin";
        if (!WriteBinaryFile(user_key_path, user_key_bytes) ||
            !LoadUserSecretKey(params, user_key, user_key_path.string())) {
            throw std::runtime_error("Failed to decode user key returned by Nitro enclave");
        }
    } catch (...) {
        CloseSocket(fd);
        std::error_code ignored;
        std::filesystem::remove_all(temp_dir, ignored);
        throw;
    }
    CloseSocket(fd);
    std::error_code ignored;
    std::filesystem::remove_all(temp_dir, ignored);
}

}  // namespace abse_zkp
