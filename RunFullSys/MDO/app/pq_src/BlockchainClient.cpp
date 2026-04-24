#include "BlockchainClient.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>

namespace {

std::string trim(std::string value) {
    while (!value.empty() && (value.back() == '\n' || value.back() == '\r' || value.back() == ' ' || value.back() == '\t')) {
        value.pop_back();
    }

    std::size_t start = 0;
    while (start < value.size() && (value[start] == ' ' || value[start] == '\t' || value[start] == '\n' || value[start] == '\r')) {
        ++start;
    }

    return value.substr(start);
}

std::string getenv_or_default(const char* name, const std::string& fallback = "") {
    const char* value = std::getenv(name);
    return value == nullptr ? fallback : std::string(value);
}

std::filesystem::path find_workspace_root() {
#ifdef ABSE_ZKP_SOURCE_DIR
    return std::filesystem::path(ABSE_ZKP_SOURCE_DIR);
#else
    std::filesystem::path current = std::filesystem::current_path();
    for (int i = 0; i < 8; ++i) {
        if (std::filesystem::exists(current / "config") &&
            std::filesystem::exists(current / "zk") &&
            std::filesystem::exists(current / "abse_src")) {
            return current;
        }
        if (!current.has_parent_path()) {
            break;
        }
        current = current.parent_path();
    }
    return std::filesystem::current_path();
#endif
}

std::map<std::string, std::string> load_config_file(const std::filesystem::path& config_path) {
    std::ifstream input(config_path);
    std::map<std::string, std::string> values;
    std::string line;

    while (std::getline(input, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') {
            continue;
        }

        const std::size_t split = line.find('=');
        if (split == std::string::npos) {
            continue;
        }

        const std::string key = trim(line.substr(0, split));
        const std::string value = trim(line.substr(split + 1));
        if (!key.empty()) {
            values[key] = value;
        }
    }

    return values;
}

std::string config_value(const std::map<std::string, std::string>& config,
                         const char* env_name,
                         const char* config_key,
                         const std::string& fallback = "") {
    const char* env_value = std::getenv(env_name);
    if (env_value != nullptr && std::string(env_value).size() > 0) {
        return std::string(env_value);
    }

    const auto it = config.find(config_key);
    if (it != config.end() && !it->second.empty()) {
        return it->second;
    }

    return fallback;
}

std::string default_cast_path() {
    const std::string home = getenv_or_default("HOME");
    if (!home.empty()) {
        const std::filesystem::path foundry_cast = std::filesystem::path(home) / ".foundry" / "bin" / "cast";
        if (std::filesystem::exists(foundry_cast)) {
            return foundry_cast.string();
        }
    }
    return "cast";
}

bool is_decimal_string(const std::string& value) {
    if (value.empty()) {
        return false;
    }
    for (char ch : value) {
        if (ch < '0' || ch > '9') {
            return false;
        }
    }
    return true;
}

std::string normalize_hex_bytes32_internal(std::string value) {
    value = trim(value);
    if (value.empty()) {
        return "0x" + std::string(64, '0');
    }

    if (!(value.rfind("0x", 0) == 0 || value.rfind("0X", 0) == 0)) {
        return value;
    }

    std::string hex = value.substr(2);
    std::transform(hex.begin(), hex.end(), hex.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });

    if (hex.size() < 64) {
        hex = std::string(64 - hex.size(), '0') + hex;
    }
    return "0x" + hex;
}

std::string decimal_string_to_bytes32_hex(std::string decimal) {
    decimal = trim(decimal);
    if (decimal.empty()) {
        return "0x" + std::string(64, '0');
    }
    if (decimal.rfind("0x", 0) == 0 || decimal.rfind("0X", 0) == 0) {
        return decimal;
    }
    if (!is_decimal_string(decimal)) {
        return decimal;
    }

    if (decimal == "0") {
        return "0x" + std::string(64, '0');
    }

    std::string hex;
    while (!(decimal.size() == 1 && decimal[0] == '0')) {
        std::string quotient;
        int remainder = 0;
        bool seen_non_zero = false;

        for (char ch : decimal) {
            const int current = remainder * 10 + (ch - '0');
            const int digit = current / 16;
            remainder = current % 16;
            if (digit != 0 || seen_non_zero) {
                quotient.push_back(static_cast<char>('0' + digit));
                seen_non_zero = true;
            }
        }

        if (quotient.empty()) {
            quotient = "0";
        }

        hex.push_back("0123456789abcdef"[remainder]);
        decimal = quotient;
    }

    std::reverse(hex.begin(), hex.end());
    if (hex.size() < 64) {
        hex = std::string(64 - hex.size(), '0') + hex;
    }
    return "0x" + hex;
}

std::string bytes32_hex_to_decimal_string(std::string hex) {
    hex = normalize_hex_bytes32_internal(hex);
    if (hex.empty()) {
        return "0";
    }
    if (!(hex.rfind("0x", 0) == 0 || hex.rfind("0X", 0) == 0)) {
        return hex;
    }

    std::string decimal = "0";
    for (std::size_t i = 2; i < hex.size(); ++i) {
        const char ch = static_cast<char>(std::tolower(static_cast<unsigned char>(hex[i])));
        int value = 0;
        if (ch >= '0' && ch <= '9') {
            value = ch - '0';
        } else if (ch >= 'a' && ch <= 'f') {
            value = 10 + (ch - 'a');
        } else {
            return hex;
        }

        int carry = value;
        for (int j = static_cast<int>(decimal.size()) - 1; j >= 0; --j) {
            const int current = (decimal[static_cast<std::size_t>(j)] - '0') * 16 + carry;
            decimal[static_cast<std::size_t>(j)] = static_cast<char>('0' + (current % 10));
            carry = current / 10;
        }
        while (carry > 0) {
            decimal.insert(decimal.begin(), static_cast<char>('0' + (carry % 10)));
            carry /= 10;
        }
    }

    const std::size_t first_non_zero = decimal.find_first_not_of('0');
    return first_non_zero == std::string::npos ? "0" : decimal.substr(first_non_zero);
}

std::string to_bytes32_hex(const std::string& decimal_or_hex) {
    const std::string trimmed = trim(decimal_or_hex);
    if (trimmed.rfind("0x", 0) == 0 || trimmed.rfind("0X", 0) == 0) {
        return normalize_hex_bytes32_internal(trimmed);
    }
    return decimal_string_to_bytes32_hex(trimmed);
}

} // namespace

BlockchainClient::BlockchainClient()
    : cast_bin(),
      rpc_url(),
      contract_address(),
      private_key() {
    const std::filesystem::path workspace_root = find_workspace_root();
    const std::filesystem::path config_path = workspace_root / "config" / "blockchain.local.conf";
    const auto config = load_config_file(config_path);

    cast_bin = config_value(config, "PQABSE_CAST_BIN", "cast_bin", default_cast_path());
    rpc_url = config_value(config, "PQABSE_CHAIN_RPC_URL", "rpc_url", "http://127.0.0.1:8545");
    contract_address = config_value(config, "PQABSE_CHAIN_CONTRACT", "contract_address");
    private_key = config_value(config, "PQABSE_CHAIN_PRIVATE_KEY", "private_key");
}

std::string BlockchainClient::normalize_hex_bytes32(const std::string& value) {
    return normalize_hex_bytes32_internal(value);
}

std::string BlockchainClient::decimal_to_hex_bytes32(const std::string& value) {
    return to_bytes32_hex(value);
}

std::string BlockchainClient::hex_bytes32_to_decimal(const std::string& value) {
    return bytes32_hex_to_decimal_string(value);
}

std::string BlockchainClient::quote_argument(const std::string& value) const {
    return "\"" + value + "\"";
}

std::string BlockchainClient::run_command_capture(const std::string& command) const {
    std::string output;
    FILE* pipe = popen(command.c_str(), "r");
    if (pipe == nullptr) {
        return output;
    }

    std::array<char, 256> buffer{};
    while (std::fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
        output += buffer.data();
    }
    pclose(pipe);
    return trim(output);
}

bool BlockchainClient::run_command(const std::string& command) const {
    return std::system((command + " >/dev/null 2>&1").c_str()) == 0;
}

bool BlockchainClient::is_configured() const {
    return !contract_address.empty();
}

bool BlockchainClient::can_broadcast() const {
    return is_configured() && !private_key.empty();
}

bool BlockchainClient::get_current_state(VersionTag& state) const {
    if (!is_configured()) {
        return false;
    }

    const std::string command = quote_argument(cast_bin) + " call " + contract_address +
                                " \"getCurrentState()(uint256,bytes32,bytes32)\" --rpc-url " +
                                quote_argument(rpc_url);
    const std::string output = run_command_capture(command);
    if (output.empty()) {
        return false;
    }

    std::istringstream input(output);
    std::string epoch_line;
    std::string registration_line;
    std::string revocation_line;

    if (!std::getline(input, epoch_line) ||
        !std::getline(input, registration_line) ||
        !std::getline(input, revocation_line)) {
        return false;
    }

    try {
        state.epoch = std::stoi(trim(epoch_line));
    } catch (...) {
        return false;
    }
    state.registration_root = normalize_hex_bytes32_internal(trim(registration_line));
    state.revocation_root = normalize_hex_bytes32_internal(trim(revocation_line));
    return true;
}

bool BlockchainClient::bootstrap_genesis_roots(const std::string& registration_root,
                                               const std::string& revocation_root) const {
    if (!can_broadcast()) {
        return false;
    }

    const std::string reg_root_hex = to_bytes32_hex(registration_root);
    const std::string rev_root_hex = to_bytes32_hex(revocation_root);
    const std::string command = quote_argument(cast_bin) + " send " + contract_address +
                                " \"bootstrapGenesisRoots(bytes32,bytes32)\" " +
                                reg_root_hex + " " + rev_root_hex +
                                " --rpc-url " + quote_argument(rpc_url) +
                                " --private-key " + quote_argument(private_key);
    return run_command(command);
}

bool BlockchainClient::update_registration_root(const std::string& registration_root) const {
    if (!can_broadcast()) {
        return false;
    }

    const std::string reg_root_hex = to_bytes32_hex(registration_root);
    const std::string command = quote_argument(cast_bin) + " send " + contract_address +
                                " \"updateRegistrationRoot(bytes32)\" " +
                                reg_root_hex +
                                " --rpc-url " + quote_argument(rpc_url) +
                                " --private-key " + quote_argument(private_key);
    return run_command(command);
}

bool BlockchainClient::update_roots(int epoch,
                                    const std::string& registration_root,
                                    const std::string& revocation_root) const {
    if (!can_broadcast()) {
        return false;
    }

    const std::string reg_root_hex = to_bytes32_hex(registration_root);
    const std::string rev_root_hex = to_bytes32_hex(revocation_root);
    const std::string command = quote_argument(cast_bin) + " send " + contract_address +
                                " \"updateRoots(uint256,bytes32,bytes32)\" " +
                                std::to_string(epoch) + " " + reg_root_hex + " " + rev_root_hex +
                                " --rpc-url " + quote_argument(rpc_url) +
                                " --private-key " + quote_argument(private_key);
    return run_command(command);
}
