#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "entities/SoftwareTee.h"
#include "system/Cli.h"
#include "system/NitroEnclaveProtocol.h"

namespace {

using namespace abse_zkp;

std::vector<std::string> SplitCsv(const std::string& value) {
    std::vector<std::string> parts;
    std::string current;
    for (char ch : value) {
        if (ch == ',') {
            if (!current.empty()) {
                parts.push_back(current);
                current.clear();
            }
        } else {
            current.push_back(ch);
        }
    }
    if (!current.empty()) {
        parts.push_back(current);
    }
    return parts;
}

std::vector<unsigned char> ToBytes(const std::string& value) {
    return std::vector<unsigned char>(value.begin(), value.end());
}

std::filesystem::path MaterializeRequest(const std::vector<EnclaveFilePacket>& files) {
    const auto temp_dir = MakeUniqueTempDir("pqabse_edge_nitro_enclave");
    for (const auto& file : files) {
        WriteBinaryFile(temp_dir / file.name, file.content);
    }
    return temp_dir;
}

std::vector<EnclaveFilePacket> HandleRequest(const std::filesystem::path& temp_dir) {
    SystemParams params{};
    PK pk;
    MSK msk;
    if (!LoadPhase1Artifacts(params, pk, msk, temp_dir.string())) {
        throw std::runtime_error("Failed to load phase1 artifacts inside Nitro enclave");
    }

    const auto bundle_label_bytes = ReadBinaryFile(temp_dir / "bundle_label.txt");
    const auto plaintext_bytes = ReadBinaryFile(temp_dir / "plaintext.txt");
    const auto keywords_bytes = ReadBinaryFile(temp_dir / "keywords.txt");
    const auto policy_bytes = ReadBinaryFile(temp_dir / "policy_expression.txt");
    const auto version_tag_bytes = ReadBinaryFile(temp_dir / "version_tag.txt");

    const std::string bundle_label(bundle_label_bytes.begin(), bundle_label_bytes.end());
    const std::string plaintext(plaintext_bytes.begin(), plaintext_bytes.end());
    const std::string keywords_text(keywords_bytes.begin(), keywords_bytes.end());
    const std::string policy_expression(policy_bytes.begin(), policy_bytes.end());
    const std::string version_tag(version_tag_bytes.begin(), version_tag_bytes.end());

    SoftwareTee tee;
    CiphertextBundle bundle;
    tee.CreateCiphertextBundle(params,
                               pk,
                               bundle_label,
                               plaintext,
                               SplitCsv(keywords_text),
                               BuildLogicalPolicyFromExpression(policy_expression),
                               version_tag,
                               bundle);

    const auto output_path = temp_dir / "ciphertext_bundle.bin";
    if (!SaveCiphertextBundle(params, bundle, output_path.string())) {
        throw std::runtime_error("Failed to save enclave-generated ciphertext bundle");
    }

    return {
        {"status.txt", ToBytes("OK")},
        {"ciphertext_bundle.bin", ReadBinaryFile(output_path)}
    };
}

}  // namespace

int main(int argc, char** argv) {
    using namespace abse_zkp;
    CliArgs cli(argc, argv);
    const std::uint32_t port = static_cast<std::uint32_t>(std::stoul(cli.Get("--port", "5005")));
    const int timeout_ms = std::stoi(cli.Get("--timeout-ms", "30000"));
    const bool once = cli.HasFlag("--once");

    const int listen_fd = ListenVsock(port);
    std::cout << "Nitro encrypt enclave server listening on vsock port " << port << std::endl;

    try {
        do {
            const int client_fd = AcceptVsock(listen_fd, timeout_ms);
            try {
                std::vector<EnclaveFilePacket> request_files;
                if (!ReceiveFilePacket(client_fd, request_files)) {
                    throw std::runtime_error("Failed to read Nitro encryption request");
                }
                const auto temp_dir = MaterializeRequest(request_files);
                std::vector<EnclaveFilePacket> response_files;
                try {
                    response_files = HandleRequest(temp_dir);
                } catch (const std::exception& ex) {
                    response_files = {
                        {"status.txt", ToBytes("ERR")},
                        {"error.txt", ToBytes(ex.what())}
                    };
                }
                SendFilePacket(client_fd, response_files);
                std::error_code ignored;
                std::filesystem::remove_all(temp_dir, ignored);
            } catch (...) {
                CloseSocket(client_fd);
                throw;
            }
            CloseSocket(client_fd);
        } while (!once);
    } catch (...) {
        CloseSocket(listen_fd);
        throw;
    }

    CloseSocket(listen_fd);
    return 0;
}
