#pragma once

#include <stdexcept>
#include <string>
#include <vector>

namespace abse_zkp {

class CliArgs {
public:
    CliArgs(int argc, char** argv) : argc_(argc), argv_(argv) {}

    bool HasFlag(const std::string& name) const {
        for (int i = 1; i < argc_; ++i) {
            if (argv_[i] == name) {
                return true;
            }
        }
        return false;
    }

    std::string Get(const std::string& name, const std::string& fallback = "") const {
        for (int i = 1; i + 1 < argc_; ++i) {
            if (argv_[i] == name) {
                return argv_[i + 1];
            }
        }
        return fallback;
    }

    std::string Require(const std::string& name) const {
        const auto value = Get(name);
        if (value.empty()) {
            throw std::runtime_error("Missing required argument: " + name);
        }
        return value;
    }

    std::vector<std::string> GetAll(const std::string& name) const {
        std::vector<std::string> values;
        for (int i = 1; i + 1 < argc_; ++i) {
            if (argv_[i] == name) {
                values.push_back(argv_[i + 1]);
            }
        }
        return values;
    }

private:
    int argc_;
    char** argv_;
};

}  // namespace abse_zkp
