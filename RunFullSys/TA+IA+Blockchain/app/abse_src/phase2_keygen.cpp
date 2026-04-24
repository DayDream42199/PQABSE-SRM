#include "phase2_keygen.h"

#include <openssl/sha.h>

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <vector>

namespace {

std::vector<std::string> CanonicalizeAttributes(const std::vector<std::string>& attributes) {
    std::vector<std::string> canonical = attributes;
    std::sort(canonical.begin(), canonical.end());
    return canonical;
}

std::vector<unsigned char> BuildEncodingSeed(const std::string& gid,
                                               const std::vector<std::string>& attributes,
                                               int epoch,
                                               const std::string& update_seed) {
    std::vector<unsigned char> seed;

    seed.insert(seed.end(), {'G', 'I', 'D', 0});
    seed.insert(seed.end(), gid.begin(), gid.end());
    seed.push_back(0xFF);

    for (const auto& attribute : attributes) {
        seed.insert(seed.end(), {'A', 'T', 'T', 'R', 0});
        seed.insert(seed.end(), attribute.begin(), attribute.end());
        seed.push_back(0xFF);
    }

    seed.insert(seed.end(), {'E', 'P', 'O', 'C', 'H', 0});
    const auto epoch_text = std::to_string(epoch);
    seed.insert(seed.end(), epoch_text.begin(), epoch_text.end());
    seed.push_back(0xFF);

    if (!update_seed.empty()) {
        seed.insert(seed.end(), {'U', 'P', 'D', 'A', 'T', 'E', 0});
        seed.insert(seed.end(), update_seed.begin(), update_seed.end());
        seed.push_back(0xFF);
    }

    return seed;
}

uint64_t HashToCoefficient(const SystemParams& params, const std::vector<unsigned char>& seed, uint32_t index) {
    std::vector<unsigned char> input = seed;
    input.push_back(static_cast<unsigned char>((index >> 24) & 0xFF));
    input.push_back(static_cast<unsigned char>((index >> 16) & 0xFF));
    input.push_back(static_cast<unsigned char>((index >> 8) & 0xFF));
    input.push_back(static_cast<unsigned char>(index & 0xFF));

    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(input.data(), input.size(), digest);

    uint64_t value = 0;
    for (int i = 0; i < 8; ++i) {
        value = (value << 8) | digest[i];
    }
    return value % params.modulus;
}

uint64_t CoefficientToUint64(const TrapdoorElement::Integer& coefficient) {
    std::ostringstream out;
    out << coefficient;
    return std::stoull(out.str());
}

TrapdoorElement MakeCoefficientElement(const SystemParams& params) {
    auto elem_params = BuildElementParams(params);
    return TrapdoorElement(elem_params, Format::COEFFICIENT, true);
}

bool WriteString(std::ostream& out, const std::string& value) {
    const uint64_t size = static_cast<uint64_t>(value.size());
    out.write(reinterpret_cast<const char*>(&size), sizeof(size));
    out.write(value.data(), static_cast<std::streamsize>(value.size()));
    return static_cast<bool>(out);
}

bool ReadString(std::istream& in, std::string& value) {
    uint64_t size = 0;
    in.read(reinterpret_cast<char*>(&size), sizeof(size));
    if (!in) {
        return false;
    }

    value.resize(static_cast<size_t>(size));
    in.read(value.data(), static_cast<std::streamsize>(size));
    return static_cast<bool>(in);
}

bool WriteStringVector(std::ostream& out, const std::vector<std::string>& values) {
    const uint64_t count = static_cast<uint64_t>(values.size());
    out.write(reinterpret_cast<const char*>(&count), sizeof(count));
    if (!out) {
        return false;
    }

    for (const auto& value : values) {
        if (!WriteString(out, value)) {
            return false;
        }
    }
    return true;
}

bool ReadStringVector(std::istream& in, std::vector<std::string>& values) {
    uint64_t count = 0;
    in.read(reinterpret_cast<char*>(&count), sizeof(count));
    if (!in) {
        return false;
    }

    values.clear();
    values.reserve(static_cast<size_t>(count));
    for (uint64_t i = 0; i < count; ++i) {
        std::string value;
        if (!ReadString(in, value)) {
            return false;
        }
        values.push_back(std::move(value));
    }
    return true;
}

bool WriteElement(std::ostream& out, const TrapdoorElement& source) {
    TrapdoorElement element = source;
    element.SetFormat(Format::COEFFICIENT);

    const uint64_t length = static_cast<uint64_t>(element.GetLength());
    out.write(reinterpret_cast<const char*>(&length), sizeof(length));
    if (!out) {
        return false;
    }

    for (uint32_t i = 0; i < element.GetLength(); ++i) {
        const uint64_t coefficient = CoefficientToUint64(element[i]);
        out.write(reinterpret_cast<const char*>(&coefficient), sizeof(coefficient));
        if (!out) {
            return false;
        }
    }

    return true;
}

bool ReadElement(std::istream& in, const SystemParams& params, TrapdoorElement& target) {
    uint64_t length = 0;
    in.read(reinterpret_cast<char*>(&length), sizeof(length));
    if (!in || length != params.ring_dim) {
        return false;
    }

    target = MakeCoefficientElement(params);
    for (uint32_t i = 0; i < params.ring_dim; ++i) {
        uint64_t coefficient = 0;
        in.read(reinterpret_cast<char*>(&coefficient), sizeof(coefficient));
        if (!in) {
            return false;
        }
        target[i] = TrapdoorElement::Integer(coefficient % params.modulus);
    }

    target.SetFormat(Format::EVALUATION);
    return true;
}

bool WriteMatrix(std::ostream& out, const TrapdoorMatrix& matrix) {
    const uint64_t rows = static_cast<uint64_t>(matrix.GetRows());
    const uint64_t cols = static_cast<uint64_t>(matrix.GetCols());
    out.write(reinterpret_cast<const char*>(&rows), sizeof(rows));
    out.write(reinterpret_cast<const char*>(&cols), sizeof(cols));
    if (!out) {
        return false;
    }

    for (uint32_t row = 0; row < matrix.GetRows(); ++row) {
        for (uint32_t col = 0; col < matrix.GetCols(); ++col) {
            if (!WriteElement(out, matrix(row, col))) {
                return false;
            }
        }
    }

    return true;
}

bool ReadMatrix(std::istream& in, const SystemParams& params, TrapdoorMatrix& matrix) {
    uint64_t rows = 0;
    uint64_t cols = 0;
    in.read(reinterpret_cast<char*>(&rows), sizeof(rows));
    in.read(reinterpret_cast<char*>(&cols), sizeof(cols));
    if (!in) {
        return false;
    }

    auto elem_params = BuildElementParams(params);
    matrix = TrapdoorMatrix(TrapdoorElement::Allocator(elem_params, Format::EVALUATION),
                            static_cast<uint32_t>(rows), static_cast<uint32_t>(cols));

    for (uint32_t row = 0; row < matrix.GetRows(); ++row) {
        for (uint32_t col = 0; col < matrix.GetCols(); ++col) {
            TrapdoorElement element;
            if (!ReadElement(in, params, element)) {
                return false;
            }
            matrix(row, col) = element;
        }
    }

    return true;
}

}  // namespace

TrapdoorElement EncodeIdentityAndAttributes(const SystemParams& params, const std::string& gid,
                                            const std::vector<std::string>& attributes,
                                            int epoch,
                                            const std::string& update_seed) {
    auto elem_params = BuildElementParams(params);
    TrapdoorElement target(elem_params, Format::COEFFICIENT, true);

    const auto canonical_attributes = CanonicalizeAttributes(attributes);
    const auto seed = BuildEncodingSeed(gid, canonical_attributes, epoch, update_seed);

    for (uint32_t i = 0; i < params.ring_dim; ++i) {
        target[i] = TrapdoorElement::Integer(HashToCoefficient(params, seed, i));
    }

    target.SetFormat(Format::EVALUATION);
    return target;
}

void KeyGen(const SystemParams& params, const PK& pk, const MSK& msk, const std::string& gid,
            const std::vector<std::string>& attributes, UserSecretKey& user_sk,
            int epoch,
            const std::string& update_seed) {
    user_sk.gid = gid;
    user_sk.attributes = CanonicalizeAttributes(attributes);
    user_sk.epoch = epoch;
    user_sk.update_seed = update_seed;
    user_sk.target_u = EncodeIdentityAndAttributes(params, gid, user_sk.attributes, user_sk.epoch, user_sk.update_seed);
    user_sk.preimage = SamplePreimage(params, pk, msk, user_sk.target_u);
}

bool VerifyUserSecretKey(const PK& pk, const UserSecretKey& user_sk) {
    return VerifyPreimage(pk, user_sk.target_u, user_sk.preimage);
}

bool SaveUserSecretKey(const SystemParams& params, const UserSecretKey& user_sk, const std::string& path) {
    std::ofstream out(path, std::ios::binary);
    if (!out.is_open()) {
        return false;
    }

    const std::string magic = "PQABSE_USERKEY_V2";
    if (!WriteString(out, magic) || !WriteString(out, user_sk.gid) ||
        !WriteStringVector(out, user_sk.attributes)) {
        return false;
    }

    out.write(reinterpret_cast<const char*>(&user_sk.epoch), sizeof(user_sk.epoch));
    if (!out || !WriteString(out, user_sk.update_seed) || !WriteElement(out, user_sk.target_u) ||
        !WriteMatrix(out, user_sk.preimage)) {
        return false;
    }

    const uint64_t ring_dim = params.ring_dim;
    out.write(reinterpret_cast<const char*>(&ring_dim), sizeof(ring_dim));
    return static_cast<bool>(out);
}

bool LoadUserSecretKey(const SystemParams& params, UserSecretKey& user_sk, const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) {
        return false;
    }

    std::string magic;
    if (!ReadString(in, magic) || (magic != "PQABSE_USERKEY_V1" && magic != "PQABSE_USERKEY_V2")) {
        return false;
    }
    if (!ReadString(in, user_sk.gid) || !ReadStringVector(in, user_sk.attributes)) {
        return false;
    }
    if (magic == "PQABSE_USERKEY_V2") {
        in.read(reinterpret_cast<char*>(&user_sk.epoch), sizeof(user_sk.epoch));
        if (!in || !ReadString(in, user_sk.update_seed)) {
            return false;
        }
    } else {
        user_sk.epoch = 0;
        user_sk.update_seed.clear();
    }
    if (!ReadElement(in, params, user_sk.target_u) || !ReadMatrix(in, params, user_sk.preimage)) {
        return false;
    }

    uint64_t ring_dim = 0;
    in.read(reinterpret_cast<char*>(&ring_dim), sizeof(ring_dim));
    return static_cast<bool>(in) && ring_dim == params.ring_dim;
}

