#include "system/AuthTokenIO.h"

#include <fstream>
#include <iomanip>
#include <map>
#include <sstream>
#include <vector>

namespace abse_zkp {
namespace {

std::string BytesToHex(const std::vector<uint8_t>& bytes) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (const auto byte : bytes) {
        out << std::setw(2) << static_cast<int>(byte);
    }
    return out.str();
}

std::vector<uint8_t> HexToBytes(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        return {};
    }
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        bytes.push_back(static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
    }
    return bytes;
}

std::string JoinStrings(const std::vector<std::string>& values) {
    std::ostringstream out;
    for (std::size_t index = 0; index < values.size(); ++index) {
        if (index > 0) {
            out << ",";
        }
        out << values[index];
    }
    return out.str();
}

std::vector<std::string> SplitStrings(const std::string& joined) {
    std::vector<std::string> values;
    std::stringstream input(joined);
    std::string item;
    while (std::getline(input, item, ',')) {
        if (!item.empty()) {
            values.push_back(item);
        }
    }
    return values;
}

}  // namespace

bool SaveAuthToken(const AuthToken& token, const std::filesystem::path& path) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::trunc);
    if (!out.is_open()) {
        return false;
    }
    out << "user_gid=" << token.user_gid << '\n';
    out << "zk_id=" << token.zk_id << '\n';
    out << "attributes=" << JoinStrings(token.attributes) << '\n';
    out << "update_token=" << token.update_token << '\n';
    out << "nonce=" << token.nonce << '\n';
    out << "issued_at_unix=" << token.issued_at_unix << '\n';
    out << "leaf_index=" << token.leaf_index << '\n';
    out << "registration_root=" << token.registration_root << '\n';
    out << "issued_epoch=" << token.issued_tag.epoch << '\n';
    out << "issued_registration_root=" << token.issued_tag.registration_root << '\n';
    out << "issued_revocation_root=" << token.issued_tag.revocation_root << '\n';
    out << "prover_state_path=" << token.prover_state_path << '\n';
    out << "proof_file_path=" << token.proof_file_path << '\n';
    out << "public_file_path=" << token.public_file_path << '\n';
    out << "prove_time_ms=" << token.prove_time_ms << '\n';
    out << "signature_hex=" << BytesToHex(token.signature) << '\n';
    return static_cast<bool>(out);
}

bool LoadAuthToken(const std::filesystem::path& path, AuthToken& token) {
    std::ifstream in(path);
    if (!in.is_open()) {
        return false;
    }
    std::map<std::string, std::string> values;
    std::string line;
    while (std::getline(in, line)) {
        const auto pos = line.find('=');
        if (pos == std::string::npos) {
            continue;
        }
        values[line.substr(0, pos)] = line.substr(pos + 1);
    }
    if (values.empty()) {
        return false;
    }
    token.user_gid = values["user_gid"];
    token.zk_id = values["zk_id"];
    token.attributes = SplitStrings(values["attributes"]);
    token.update_token = values["update_token"];
    token.nonce = std::stoi(values["nonce"]);
    token.issued_at_unix = std::stoll(values["issued_at_unix"]);
    token.leaf_index = std::stoi(values["leaf_index"]);
    token.registration_root = values["registration_root"];
    token.issued_tag.epoch = std::stoi(values["issued_epoch"]);
    token.issued_tag.registration_root = values["issued_registration_root"];
    token.issued_tag.revocation_root = values["issued_revocation_root"];
    token.prover_state_path = values["prover_state_path"];
    token.proof_file_path = values["proof_file_path"];
    token.public_file_path = values["public_file_path"];
    token.prove_time_ms = values["prove_time_ms"].empty() ? 0.0 : std::stod(values["prove_time_ms"]);
    token.signature = HexToBytes(values["signature_hex"]);
    return true;
}

}  // namespace abse_zkp
