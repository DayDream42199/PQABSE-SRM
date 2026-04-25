#include <filesystem>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

#include "entities/SoftwareTee.h"
#include "system/Cli.h"
#include "system/NitroEnclaveProtocol.h"

namespace {

using namespace abse_zkp;

std::map<std::string, std::string> ParseKeyValues(const std::string& content) {
    std::map<std::string, std::string> values;
    std::size_t start = 0;
    while (start < content.size()) {
        const auto end = content.find('\n', start);
        const auto line = content.substr(start, end == std::string::npos ? std::string::npos : end - start);
        const auto split = line.find('=');
        if (split != std::string::npos) {
            values[line.substr(0, split)] = line.substr(split + 1);
        }
        if (end == std::string::npos) {
            break;
        }
        start = end + 1;
    }
    return values;
}

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
    const auto temp_dir = MakeUniqueTempDir("pqabse_ta_nitro_enclave");
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

    const auto request_content = ReadBinaryFile(temp_dir / "keygen_request.txt");
    const auto request_values = ParseKeyValues(std::string(request_content.begin(), request_content.end()));
    const auto gid_it = request_values.find("gid");
    if (gid_it == request_values.end()) {
        throw std::runtime_error("Missing gid in keygen request");
    }
    const auto attributes = SplitCsv(request_values["attributes"]);
    const int epoch = request_values.count("epoch") ? std::stoi(request_values["epoch"]) : 0;
    const std::string update_seed = request_values.count("update_seed") ? request_values["update_seed"] : "";

    SoftwareTee tee;
    UserSecretKey user_key;
    tee.GenerateUserKey(params, pk, msk, gid_it->second, attributes, user_key, epoch, update_seed);

    const auto output_path = temp_dir / "user_key.bin";
    if (!SaveUserSecretKey(params, user_key, output_path.string())) {
        throw std::runtime_error("Failed to save enclave-generated user key");
    }

    return {
        {"status.txt", ToBytes("OK")},
        {"user_key.bin", ReadBinaryFile(output_path)}
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
    std::cout << "Nitro keygen enclave server listening on vsock port " << port << std::endl;

    try {
        do {
            const int client_fd = AcceptVsock(listen_fd, timeout_ms);
            try {
                std::vector<EnclaveFilePacket> request_files;
                if (!ReceiveFilePacket(client_fd, request_files)) {
                    throw std::runtime_error("Failed to read Nitro keygen request");
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
