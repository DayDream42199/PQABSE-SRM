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

void NitroTeeClient::CreateCiphertextBundle(const SystemParams& params,
                                            const PK& pk,
                                            const MSK& msk,
                                            const std::string& bundle_label,
                                            const std::string& plaintext,
                                            const std::vector<std::string>& keywords,
                                            const LogicalPolicy& logical_policy,
                                            const std::string& version_tag,
                                            CiphertextBundle& bundle,
                                            const NitroTeeOptions& options) const {
    const auto temp_dir = MakeUniqueTempDir("pqabse_edge_nitro_parent");
    if (!SavePhase1Artifacts(params, pk, msk, temp_dir.string())) {
        std::error_code ignored;
        std::filesystem::remove_all(temp_dir, ignored);
        throw std::runtime_error("Failed to stage phase1 artifacts for Nitro enclave encryption");
    }

    std::vector<EnclaveFilePacket> request_files;
    request_files.push_back({"phase1_params.txt", ReadBinaryFile(temp_dir / "phase1_params.txt")});
    request_files.push_back({"phase1_public_key.bin", ReadBinaryFile(temp_dir / "phase1_public_key.bin")});
    request_files.push_back({"phase1_trapdoor.bin", ReadBinaryFile(temp_dir / "phase1_trapdoor.bin")});
    request_files.push_back({"bundle_label.txt", ToBytes(bundle_label)});
    request_files.push_back({"plaintext.txt", ToBytes(plaintext)});
    request_files.push_back({"keywords.txt", ToBytes(JoinStrings(keywords))});
    request_files.push_back({"policy_expression.txt", ToBytes(DescribeLogicalPolicy(logical_policy))});
    request_files.push_back({"version_tag.txt", ToBytes(version_tag)});

    const int fd = ConnectVsock(options.enclave_cid, options.port, options.timeout_ms);
    try {
        if (!SendFilePacket(fd, request_files)) {
            throw std::runtime_error("Failed to send encryption request to Nitro enclave");
        }
        std::vector<EnclaveFilePacket> response_files;
        if (!ReceiveFilePacket(fd, response_files)) {
            throw std::runtime_error("Failed to receive encryption response from Nitro enclave");
        }
        const auto status = ReadStatus(response_files);
        if (status != "OK") {
            const auto error_bytes = FindPacketContent(response_files, "error.txt");
            throw std::runtime_error("Nitro enclave encryption failed: " +
                                     std::string(error_bytes.begin(), error_bytes.end()));
        }
        const auto bundle_bytes = FindPacketContent(response_files, "ciphertext_bundle.bin");
        if (bundle_bytes.empty()) {
            throw std::runtime_error("Nitro enclave encryption response missing ciphertext_bundle.bin");
        }
        const auto bundle_path = temp_dir / "ciphertext_bundle.bin";
        if (!WriteBinaryFile(bundle_path, bundle_bytes) ||
            !LoadCiphertextBundle(params, bundle, bundle_path.string())) {
            throw std::runtime_error("Failed to decode ciphertext bundle returned by Nitro enclave");
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
