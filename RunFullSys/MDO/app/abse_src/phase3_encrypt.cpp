#include "phase3_encrypt.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <set>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace {

uint64_t CoefficientToUint64(const TrapdoorElement::Integer& coefficient) {
    std::ostringstream out;
    out << coefficient;
    return std::stoull(out.str());
}

TrapdoorElement MakeCoefficientElement(const SystemParams& params) {
    auto elem_params = BuildElementParams(params);
    return TrapdoorElement(elem_params, Format::COEFFICIENT, true);
}

std::vector<std::string> CanonicalizeStrings(const std::vector<std::string>& values) {
    std::vector<std::string> canonical = values;
    std::sort(canonical.begin(), canonical.end());
    canonical.erase(std::unique(canonical.begin(), canonical.end()), canonical.end());
    return canonical;
}

std::vector<unsigned char> BytesFromArray(const std::array<unsigned char, 16>& value) {
    return std::vector<unsigned char>(value.begin(), value.end());
}

std::vector<unsigned char> BytesFromArray(const std::array<unsigned char, 32>& value) {
    return std::vector<unsigned char>(value.begin(), value.end());
}

std::array<unsigned char, 32> HashUpdateMaterial(const std::string& update_material) {
    std::array<unsigned char, 32> digest{};
    if (update_material.empty()) {
        return digest;
    }
    SHA256(reinterpret_cast<const unsigned char*>(update_material.data()), update_material.size(), digest.data());
    return digest;
}

bool IsZeroCommitment(const std::array<unsigned char, 32>& commitment) {
    return std::all_of(commitment.begin(), commitment.end(), [](unsigned char value) { return value == 0; });
}

void MixHash(const std::vector<unsigned char>& seed, uint32_t index, unsigned char digest[SHA256_DIGEST_LENGTH]) {
    std::vector<unsigned char> input = seed;
    input.push_back(static_cast<unsigned char>((index >> 24) & 0xFF));
    input.push_back(static_cast<unsigned char>((index >> 16) & 0xFF));
    input.push_back(static_cast<unsigned char>((index >> 8) & 0xFF));
    input.push_back(static_cast<unsigned char>(index & 0xFF));
    SHA256(input.data(), input.size(), digest);
}

TrapdoorElement SampleUniformElement(const SystemParams& params, const std::vector<unsigned char>& seed,
                                     uint32_t offset) {
    TrapdoorElement element = MakeCoefficientElement(params);
    unsigned char digest[SHA256_DIGEST_LENGTH];
    for (uint32_t i = 0; i < params.ring_dim; ++i) {
        MixHash(seed, offset + i, digest);
        uint64_t value = 0;
        for (int j = 0; j < 8; ++j) {
            value = (value << 8) | digest[j];
        }
        element[i] = TrapdoorElement::Integer(value % params.modulus);
    }
    element.SetFormat(Format::EVALUATION);
    return element;
}

std::vector<unsigned char> BuildCiphertextBindingSeed(const AccessPolicy& policy,
                                                   const std::string& version_tag,
                                                   const std::array<unsigned char, 16>& file_nonce,
                                                   const std::string& re_encryption_material) {
    std::vector<unsigned char> seed;
    seed.insert(seed.end(), policy.descriptor.begin(), policy.descriptor.end());
    seed.push_back(0xFF);
    for (const auto& attribute : policy.rho) {
        seed.insert(seed.end(), attribute.begin(), attribute.end());
        seed.push_back(0xFE);
    }
    seed.insert(seed.end(), {'V', 'E', 'R', 0});
    seed.insert(seed.end(), version_tag.begin(), version_tag.end());
    seed.push_back(0xFF);
    seed.insert(seed.end(), {'N', 'O', 'N', 'C', 'E', 0});
    seed.insert(seed.end(), file_nonce.begin(), file_nonce.end());
    seed.push_back(0xFF);
    if (!re_encryption_material.empty()) {
        unsigned char digest[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(re_encryption_material.data()), re_encryption_material.size(), digest);
        seed.insert(seed.end(), {'R', 'E', 'K', 'E', 'Y', 0});
        seed.insert(seed.end(), digest, digest + SHA256_DIGEST_LENGTH);
        seed.push_back(0xFF);
    }
    return seed;
}

TrapdoorElement EncodeBoundAccessPolicy(const SystemParams& params, const AccessPolicy& policy,
                                        const std::string& version_tag,
                                        const std::array<unsigned char, 16>& file_nonce,
                                        const std::string& re_encryption_material) {
    auto seed = BuildCiphertextBindingSeed(policy, version_tag, file_nonce, re_encryption_material);
    seed.insert(seed.end(), policy.descriptor.begin(), policy.descriptor.end());
    return SampleUniformElement(params, seed, 0);
}

TrapdoorElement EncodeEpochBinding(const SystemParams& params, const AccessPolicy& policy,
                                   const std::string& version_tag,
                                   const std::array<unsigned char, 16>& file_nonce,
                                   const std::string& re_encryption_material) {
    auto seed = BuildCiphertextBindingSeed(policy, version_tag, file_nonce, re_encryption_material);
    seed.insert(seed.end(), {'E', 'P', 'O', 'C', 'H', 0});
    return SampleUniformElement(params, seed, params.ring_dim);
}

std::array<unsigned char, 32> DeriveMask(const TrapdoorElement& header, const TrapdoorElement& policy_tag,
                                         const TrapdoorElement* epoch_tag = nullptr,
                                         const std::string& reencryption_tag = "",
                                         const std::array<unsigned char, 32>* update_seed_commitment = nullptr) {
    TrapdoorElement header_copy = header;
    TrapdoorElement policy_copy = policy_tag;
    header_copy.SetFormat(Format::COEFFICIENT);
    policy_copy.SetFormat(Format::COEFFICIENT);

    std::vector<unsigned char> input;
    for (uint32_t i = 0; i < header_copy.GetLength(); ++i) {
        const uint64_t value = CoefficientToUint64(header_copy[i]);
        input.push_back(static_cast<unsigned char>(value & 0xFF));
        input.push_back(static_cast<unsigned char>((value >> 8) & 0xFF));
    }
    for (uint32_t i = 0; i < policy_copy.GetLength(); ++i) {
        const uint64_t value = CoefficientToUint64(policy_copy[i]);
        input.push_back(static_cast<unsigned char>(value & 0xFF));
        input.push_back(static_cast<unsigned char>((value >> 8) & 0xFF));
    }
    if (!reencryption_tag.empty() && epoch_tag != nullptr) {
        TrapdoorElement epoch_copy = *epoch_tag;
        epoch_copy.SetFormat(Format::COEFFICIENT);
        for (uint32_t i = 0; i < epoch_copy.GetLength(); ++i) {
            const uint64_t value = CoefficientToUint64(epoch_copy[i]);
            input.push_back(static_cast<unsigned char>(value & 0xFF));
            input.push_back(static_cast<unsigned char>((value >> 8) & 0xFF));
        }
        input.insert(input.end(), reencryption_tag.begin(), reencryption_tag.end());
    }
    if (update_seed_commitment != nullptr && !IsZeroCommitment(*update_seed_commitment)) {
        input.insert(input.end(), update_seed_commitment->begin(), update_seed_commitment->end());
    }

    std::array<unsigned char, 32> mask{};
    SHA256(input.data(), input.size(), mask.data());
    return mask;
}

bool FillRandom(unsigned char* buffer, size_t size) {
    return RAND_bytes(buffer, static_cast<int>(size)) == 1;
}

std::vector<std::string> CollectLeafAttributes(const LogicalPolicy& policy) {
    if (policy.kind == PolicyKind::Attribute) {
        return {policy.attribute};
    }

    std::vector<std::string> leaves;
    for (const auto& child : policy.children) {
        const auto child_leaves = CollectLeafAttributes(child);
        leaves.insert(leaves.end(), child_leaves.begin(), child_leaves.end());
    }
    return CanonicalizeStrings(leaves);
}

bool IsFlatLeafOnly(const LogicalPolicy& policy) {
    if (policy.kind == PolicyKind::Attribute) {
        return true;
    }
    return !policy.children.empty() && std::all_of(policy.children.begin(), policy.children.end(), [](const LogicalPolicy& child) {
        return child.kind == PolicyKind::Attribute;
    });
}

std::vector<unsigned char> SerializePolicy(const AccessPolicy& policy) {
    std::vector<unsigned char> bytes;
    bytes.insert(bytes.end(), policy.descriptor.begin(), policy.descriptor.end());
    bytes.push_back(0xFF);
    bytes.push_back(static_cast<unsigned char>(policy.is_summary ? 1 : 0));
    for (const auto& row : policy.matrix) {
        bytes.push_back(static_cast<unsigned char>('R'));
        for (auto value : row) {
            const auto text = std::to_string(value);
            bytes.insert(bytes.end(), text.begin(), text.end());
            bytes.push_back(static_cast<unsigned char>(','));
        }
        bytes.push_back(static_cast<unsigned char>(';'));
    }
    for (const auto& attribute : policy.rho) {
        bytes.push_back(static_cast<unsigned char>('A'));
        bytes.insert(bytes.end(), attribute.begin(), attribute.end());
        bytes.push_back(static_cast<unsigned char>(';'));
    }
    return bytes;
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

bool WriteByteVector(std::ostream& out, const std::vector<unsigned char>& value) {
    const uint64_t size = static_cast<uint64_t>(value.size());
    out.write(reinterpret_cast<const char*>(&size), sizeof(size));
    if (!out) {
        return false;
    }
    out.write(reinterpret_cast<const char*>(value.data()), static_cast<std::streamsize>(value.size()));
    return static_cast<bool>(out);
}

bool ReadByteVector(std::istream& in, std::vector<unsigned char>& value) {
    uint64_t size = 0;
    in.read(reinterpret_cast<char*>(&size), sizeof(size));
    if (!in) {
        return false;
    }
    value.resize(static_cast<size_t>(size));
    in.read(reinterpret_cast<char*>(value.data()), static_cast<std::streamsize>(size));
    return static_cast<bool>(in);
}

bool WriteLogicalPolicy(std::ostream& out, const LogicalPolicy& logical_policy) {
    const uint64_t kind = static_cast<uint64_t>(logical_policy.kind);
    const uint64_t threshold = static_cast<uint64_t>(logical_policy.threshold);
    const uint64_t child_count = static_cast<uint64_t>(logical_policy.children.size());
    out.write(reinterpret_cast<const char*>(&kind), sizeof(kind));
    out.write(reinterpret_cast<const char*>(&threshold), sizeof(threshold));
    if (!WriteString(out, logical_policy.attribute)) {
        return false;
    }
    out.write(reinterpret_cast<const char*>(&child_count), sizeof(child_count));
    if (!out) {
        return false;
    }
    for (const auto& child : logical_policy.children) {
        if (!WriteLogicalPolicy(out, child)) {
            return false;
        }
    }
    return true;
}

bool ReadLogicalPolicy(std::istream& in, LogicalPolicy& logical_policy) {
    uint64_t kind = 0;
    uint64_t threshold = 0;
    uint64_t child_count = 0;
    in.read(reinterpret_cast<char*>(&kind), sizeof(kind));
    in.read(reinterpret_cast<char*>(&threshold), sizeof(threshold));
    if (!in || !ReadString(in, logical_policy.attribute)) {
        return false;
    }
    in.read(reinterpret_cast<char*>(&child_count), sizeof(child_count));
    if (!in) {
        return false;
    }
    logical_policy.kind = static_cast<PolicyKind>(kind);
    logical_policy.threshold = static_cast<size_t>(threshold);
    logical_policy.children.resize(static_cast<size_t>(child_count));
    for (auto& child : logical_policy.children) {
        if (!ReadLogicalPolicy(in, child)) {
            return false;
        }
    }
    return true;
}

bool WritePolicy(std::ostream& out, const AccessPolicy& policy) {
    const uint64_t rows = static_cast<uint64_t>(policy.matrix.size());
    out.write(reinterpret_cast<const char*>(&rows), sizeof(rows));
    if (!out || !WriteString(out, policy.descriptor)) {
        return false;
    }
    const unsigned char is_summary = policy.is_summary ? 1 : 0;
    out.write(reinterpret_cast<const char*>(&is_summary), sizeof(is_summary));
    if (!out) {
        return false;
    }
    for (const auto& row : policy.matrix) {
        const uint64_t cols = static_cast<uint64_t>(row.size());
        out.write(reinterpret_cast<const char*>(&cols), sizeof(cols));
        if (!out) {
            return false;
        }
        for (auto value : row) {
            out.write(reinterpret_cast<const char*>(&value), sizeof(value));
            if (!out) {
                return false;
            }
        }
    }
    const uint64_t rho_count = static_cast<uint64_t>(policy.rho.size());
    out.write(reinterpret_cast<const char*>(&rho_count), sizeof(rho_count));
    if (!out) {
        return false;
    }
    for (const auto& label : policy.rho) {
        if (!WriteString(out, label)) {
            return false;
        }
    }
    return true;
}

bool ReadPolicy(std::istream& in, AccessPolicy& policy) {
    uint64_t rows = 0;
    in.read(reinterpret_cast<char*>(&rows), sizeof(rows));
    if (!in || !ReadString(in, policy.descriptor)) {
        return false;
    }
    unsigned char is_summary = 0;
    in.read(reinterpret_cast<char*>(&is_summary), sizeof(is_summary));
    if (!in) {
        return false;
    }
    policy.is_summary = (is_summary != 0);
    policy.matrix.clear();
    policy.matrix.reserve(static_cast<size_t>(rows));
    for (uint64_t row = 0; row < rows; ++row) {
        uint64_t cols = 0;
        in.read(reinterpret_cast<char*>(&cols), sizeof(cols));
        if (!in) {
            return false;
        }
        std::vector<int64_t> row_values(static_cast<size_t>(cols));
        for (uint64_t col = 0; col < cols; ++col) {
            in.read(reinterpret_cast<char*>(&row_values[col]), sizeof(row_values[col]));
            if (!in) {
                return false;
            }
        }
        policy.matrix.push_back(std::move(row_values));
    }
    uint64_t rho_count = 0;
    in.read(reinterpret_cast<char*>(&rho_count), sizeof(rho_count));
    if (!in) {
        return false;
    }
    policy.rho.clear();
    policy.rho.reserve(static_cast<size_t>(rho_count));
    for (uint64_t i = 0; i < rho_count; ++i) {
        std::string label;
        if (!ReadString(in, label)) {
            return false;
        }
        policy.rho.push_back(std::move(label));
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

bool WriteKeywordSet(std::ostream& out, const std::vector<std::string>& keywords) {
    const uint64_t count = static_cast<uint64_t>(keywords.size());
    out.write(reinterpret_cast<const char*>(&count), sizeof(count));
    if (!out) {
        return false;
    }
    for (const auto& keyword : keywords) {
        if (!WriteString(out, keyword)) {
            return false;
        }
    }
    return true;
}

bool ReadKeywordSet(std::istream& in, std::vector<std::string>& keywords) {
    uint64_t count = 0;
    in.read(reinterpret_cast<char*>(&count), sizeof(count));
    if (!in) {
        return false;
    }
    keywords.clear();
    keywords.reserve(static_cast<size_t>(count));
    for (uint64_t i = 0; i < count; ++i) {
        std::string keyword;
        if (!ReadString(in, keyword)) {
            return false;
        }
        keywords.push_back(std::move(keyword));
    }
    return true;
}

int64_t PowInt(int64_t base, size_t exponent) {
    int64_t result = 1;
    for (size_t i = 0; i < exponent; ++i) {
        result *= base;
    }
    return result;
}

bool EvaluatePolicy(const std::set<std::string>& attributes, const LogicalPolicy& policy) {
    switch (policy.kind) {
        case PolicyKind::Attribute:
            return attributes.find(policy.attribute) != attributes.end();
        case PolicyKind::And:
            return std::all_of(policy.children.begin(), policy.children.end(), [&](const LogicalPolicy& child) {
                return EvaluatePolicy(attributes, child);
            });
        case PolicyKind::Or:
            return std::any_of(policy.children.begin(), policy.children.end(), [&](const LogicalPolicy& child) {
                return EvaluatePolicy(attributes, child);
            });
        case PolicyKind::Threshold: {
            size_t matches = 0;
            for (const auto& child : policy.children) {
                if (EvaluatePolicy(attributes, child)) {
                    ++matches;
                }
            }
            return matches >= policy.threshold;
        }
    }
    return false;
}

}  // namespace

LogicalPolicy MakeAttributePolicy(const std::string& attribute) {
    if (attribute.empty()) {
        throw std::invalid_argument("attribute policy cannot be empty");
    }
    return LogicalPolicy{PolicyKind::Attribute, 1, attribute, {}};
}

LogicalPolicy MakeAndPolicy(const std::vector<std::string>& attributes) {
    std::vector<LogicalPolicy> children;
    for (const auto& attribute : CanonicalizeStrings(attributes)) {
        children.push_back(MakeAttributePolicy(attribute));
    }
    return MakeAndPolicy(children);
}

LogicalPolicy MakeAndPolicy(const std::vector<LogicalPolicy>& children) {
    if (children.empty()) {
        throw std::invalid_argument("AND policy requires children");
    }
    return LogicalPolicy{PolicyKind::And, children.size(), "", children};
}

LogicalPolicy MakeOrPolicy(const std::vector<std::string>& attributes) {
    std::vector<LogicalPolicy> children;
    for (const auto& attribute : CanonicalizeStrings(attributes)) {
        children.push_back(MakeAttributePolicy(attribute));
    }
    return MakeOrPolicy(children);
}

LogicalPolicy MakeOrPolicy(const std::vector<LogicalPolicy>& children) {
    if (children.empty()) {
        throw std::invalid_argument("OR policy requires children");
    }
    return LogicalPolicy{PolicyKind::Or, 1, "", children};
}

LogicalPolicy MakeThresholdPolicy(size_t threshold, const std::vector<std::string>& attributes) {
    std::vector<LogicalPolicy> children;
    for (const auto& attribute : CanonicalizeStrings(attributes)) {
        children.push_back(MakeAttributePolicy(attribute));
    }
    return MakeThresholdPolicy(threshold, children);
}

LogicalPolicy MakeThresholdPolicy(size_t threshold, const std::vector<LogicalPolicy>& children) {
    if (children.empty() || threshold == 0 || threshold > children.size()) {
        throw std::invalid_argument("invalid threshold policy");
    }
    if (threshold == 1) {
        return MakeOrPolicy(children);
    }
    if (threshold == children.size()) {
        return MakeAndPolicy(children);
    }
    return LogicalPolicy{PolicyKind::Threshold, threshold, "", children};
}

AccessPolicy BuildAccessPolicy(const LogicalPolicy& logical_policy) {
    AccessPolicy policy;
    policy.descriptor = DescribeLogicalPolicy(logical_policy);
    policy.rho = CollectLeafAttributes(logical_policy);
    policy.is_summary = !IsFlatLeafOnly(logical_policy);

    if (logical_policy.kind == PolicyKind::Attribute) {
        policy.matrix = {{1}};
        return policy;
    }

    if (!policy.is_summary) {
        const size_t threshold = logical_policy.kind == PolicyKind::Threshold ? logical_policy.threshold : (logical_policy.kind == PolicyKind::Or ? 1 : logical_policy.children.size());
        for (size_t row = 0; row < logical_policy.children.size(); ++row) {
            std::vector<int64_t> row_values;
            row_values.reserve(threshold);
            const int64_t x = static_cast<int64_t>(row + 1);
            for (size_t col = 0; col < threshold; ++col) {
                row_values.push_back(PowInt(x, col));
            }
            policy.matrix.push_back(std::move(row_values));
        }
        return policy;
    }

    policy.matrix.assign(policy.rho.size(), std::vector<int64_t>(policy.rho.size(), 0));
    for (size_t i = 0; i < policy.rho.size(); ++i) {
        policy.matrix[i][i] = 1;
    }
    return policy;
}

std::string DescribeLogicalPolicy(const LogicalPolicy& logical_policy) {
    if (logical_policy.kind == PolicyKind::Attribute) {
        return logical_policy.attribute;
    }

    std::ostringstream out;
    switch (logical_policy.kind) {
        case PolicyKind::And:
            out << "AND(";
            break;
        case PolicyKind::Or:
            out << "OR(";
            break;
        case PolicyKind::Threshold:
            out << logical_policy.threshold << "-of-" << logical_policy.children.size() << "(";
            break;
        case PolicyKind::Attribute:
            break;
    }
    for (size_t i = 0; i < logical_policy.children.size(); ++i) {
        if (i != 0) {
            out << ", ";
        }
        out << DescribeLogicalPolicy(logical_policy.children[i]);
    }
    out << ')';
    return out.str();
}

TrapdoorElement EncodeAccessPolicy(const SystemParams& params, const AccessPolicy& policy) {
    return SampleUniformElement(params, SerializePolicy(policy), 0);
}

TrapdoorElement EncodeKeywordToken(const SystemParams& params, const std::string& keyword,
                                   const std::array<unsigned char, 16>& file_nonce) {
    (void)file_nonce;
    std::vector<unsigned char> seed = {static_cast<unsigned char>('K'), static_cast<unsigned char>('W'), 0};
    seed.insert(seed.end(), keyword.begin(), keyword.end());
    return SampleUniformElement(params, seed, 0);
}

std::array<unsigned char, 32> GenerateSessionKey() {
    std::array<unsigned char, 32> session_key{};
    if (!FillRandom(session_key.data(), session_key.size())) {
        throw std::runtime_error("RAND_bytes failed while generating session key");
    }
    return session_key;
}

bool EncryptData(const std::array<unsigned char, 32>& session_key, const std::string& plaintext,
                 std::vector<unsigned char>& nonce, std::vector<unsigned char>& ciphertext,
                 std::vector<unsigned char>& auth_tag) {
    nonce.resize(12);
    auth_tag.resize(16);
    ciphertext.resize(plaintext.size());
    if (!FillRandom(nonce.data(), nonce.size())) {
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        return false;
    }

    int len = 0;
    int ciphertext_len = 0;
    bool ok = EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) == 1 &&
              EVP_EncryptInit_ex(ctx, nullptr, nullptr, session_key.data(), nonce.data()) == 1 &&
              EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                                reinterpret_cast<const unsigned char*>(plaintext.data()),
                                static_cast<int>(plaintext.size())) == 1;
    if (ok) {
        ciphertext_len = len;
        ok = EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) == 1;
    }
    if (ok) {
        ciphertext_len += len;
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, static_cast<int>(auth_tag.size()), auth_tag.data()) == 1;
    }

    EVP_CIPHER_CTX_free(ctx);
    if (!ok) {
        return false;
    }
    ciphertext.resize(static_cast<size_t>(ciphertext_len));
    return true;
}

bool DecryptData(const std::array<unsigned char, 32>& session_key, const std::vector<unsigned char>& nonce,
                 const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& auth_tag,
                 std::string& plaintext_out) {
    std::vector<unsigned char> plaintext(ciphertext.size());
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        return false;
    }

    int len = 0;
    int plaintext_len = 0;
    bool ok = EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) == 1 &&
              EVP_DecryptInit_ex(ctx, nullptr, nullptr, session_key.data(), nonce.data()) == 1 &&
              EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), static_cast<int>(ciphertext.size())) == 1;
    if (ok) {
        plaintext_len = len;
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, static_cast<int>(auth_tag.size()),
                                 const_cast<unsigned char*>(auth_tag.data())) == 1;
    }
    if (ok) {
        ok = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) == 1;
    }
    if (ok) {
        plaintext_len += len;
    }

    EVP_CIPHER_CTX_free(ctx);
    if (!ok) {
        return false;
    }

    plaintext.resize(static_cast<size_t>(plaintext_len));
    plaintext_out.assign(reinterpret_cast<const char*>(plaintext.data()), plaintext.size());
    return true;
}

void EncABSE(const SystemParams& params, const PK& pk, const std::array<unsigned char, 32>& session_key,
             const AccessPolicy& policy, const std::string& version_tag,
             const std::array<unsigned char, 16>& file_nonce,
             const std::string& re_encryption_material,
             const std::string& user_update_material,
             CiphertextKey& ciphertext) {
    ciphertext.policy = policy;
    ciphertext.reencryption_tag = version_tag;
    ciphertext.update_seed_commitment = HashUpdateMaterial(user_update_material);
    ciphertext.policy_tag = EncodeBoundAccessPolicy(params, policy, version_tag, file_nonce, re_encryption_material);
    ciphertext.epoch_tag = EncodeEpochBinding(params, policy, version_tag, file_nonce, re_encryption_material);

    std::vector<unsigned char> seed = BytesFromArray(session_key);
    auto binding_seed = BuildCiphertextBindingSeed(policy, version_tag, file_nonce, re_encryption_material);
    seed.insert(seed.end(), binding_seed.begin(), binding_seed.end());
    seed.insert(seed.end(), policy.descriptor.begin(), policy.descriptor.end());
    (void)pk;
    ciphertext.header_u = SampleUniformElement(params, seed, 2 * params.ring_dim);

    const auto mask = DeriveMask(ciphertext.header_u, ciphertext.policy_tag, &ciphertext.epoch_tag,
                                 ciphertext.reencryption_tag, &ciphertext.update_seed_commitment);
    for (size_t i = 0; i < ciphertext.encrypted_session_key.size(); ++i) {
        ciphertext.encrypted_session_key[i] = static_cast<unsigned char>(session_key[i] ^ mask[i]);
    }
}

bool PolicySatisfied(const std::vector<std::string>& user_attributes, const LogicalPolicy& logical_policy) {
    const auto canonical = CanonicalizeStrings(user_attributes);
    const std::set<std::string> attribute_set(canonical.begin(), canonical.end());
    return EvaluatePolicy(attribute_set, logical_policy);
}

bool DecABSE(const SystemParams& params, const UserSecretKey& user_sk,
             const LogicalPolicy& logical_policy, const CiphertextKey& ciphertext,
             std::array<unsigned char, 32>& session_key_out) {
    (void)params;
    if (!PolicySatisfied(user_sk.attributes, logical_policy)) {
        return false;
    }
    const auto expected_commitment = HashUpdateMaterial(user_sk.update_seed);
    if (ciphertext.update_seed_commitment != expected_commitment) {
        return false;
    }
    const TrapdoorElement* epoch_tag = ciphertext.reencryption_tag.empty() ? nullptr : &ciphertext.epoch_tag;
    const auto mask = DeriveMask(ciphertext.header_u, ciphertext.policy_tag, epoch_tag,
                                 ciphertext.reencryption_tag, &ciphertext.update_seed_commitment);
    for (size_t i = 0; i < session_key_out.size(); ++i) {
        session_key_out[i] = static_cast<unsigned char>(ciphertext.encrypted_session_key[i] ^ mask[i]);
    }
    return true;
}

void ReEncryptCiphertextBundle(const SystemParams& params, CiphertextBundle& bundle,
                             const std::string& next_version_tag,
                             const std::string& re_encryption_material,
                             const std::string& user_update_material) {
    std::array<unsigned char, 32> session_key{};
    const TrapdoorElement* epoch_tag = bundle.ctk.reencryption_tag.empty() ? nullptr : &bundle.ctk.epoch_tag;
    const auto previous_mask = DeriveMask(bundle.ctk.header_u, bundle.ctk.policy_tag, epoch_tag,
                                          bundle.ctk.reencryption_tag, &bundle.ctk.update_seed_commitment);
    for (size_t i = 0; i < session_key.size(); ++i) {
        session_key[i] = static_cast<unsigned char>(bundle.ctk.encrypted_session_key[i] ^ previous_mask[i]);
    }

    std::string verified_plaintext;
    if (!DecryptData(session_key, bundle.nonce, bundle.ctdata, bundle.auth_tag, verified_plaintext)) {
        throw std::runtime_error("Failed to unwrap session key during ciphertext re-encryption");
    }

    bundle.version_tag = next_version_tag;
    PK placeholder_pk;
    EncABSE(params, placeholder_pk, session_key, bundle.policy, bundle.version_tag, bundle.file_nonce,
            re_encryption_material, user_update_material, bundle.ctk);
}

std::vector<TrapdoorElement> BuildSecureIndex(const SystemParams& params,
                                              const std::vector<std::string>& keywords,
                                              const std::array<unsigned char, 16>& file_nonce) {
    const auto canonical_keywords = CanonicalizeStrings(keywords);
    std::vector<TrapdoorElement> secure_index;
    secure_index.reserve(canonical_keywords.size());
    for (const auto& keyword : canonical_keywords) {
        secure_index.push_back(EncodeKeywordToken(params, keyword, file_nonce));
    }
    return secure_index;
}

void AssembleCiphertextBundle(const SystemParams& params, const PK& pk, const std::string& bundle_label,
                              const std::string& plaintext, const std::vector<std::string>& keywords,
                              const LogicalPolicy& logical_policy, const std::string& version_tag,
                              CiphertextBundle& bundle, double* mobile_encrypt_ms) {
    const auto mobile_encrypt_start = std::chrono::high_resolution_clock::now();
    const auto session_key = GenerateSessionKey();
    if (!EncryptData(session_key, plaintext, bundle.nonce, bundle.ctdata, bundle.auth_tag)) {
        throw std::runtime_error("ChaCha20-Poly1305 encryption failed");
    }

    bundle.bundle_label = bundle_label;
    bundle.logical_policy = logical_policy;
    bundle.policy = BuildAccessPolicy(logical_policy);
    bundle.keyword_set = CanonicalizeStrings(keywords);
    bundle.version_tag = version_tag;
    if (!FillRandom(bundle.file_nonce.data(), bundle.file_nonce.size())) {
        throw std::runtime_error("RAND_bytes failed while generating file nonce");
    }

    EncABSE(params, pk, session_key, bundle.policy, bundle.version_tag, bundle.file_nonce, "", "", bundle.ctk);
    if (mobile_encrypt_ms != nullptr) {
        const auto mobile_encrypt_end = std::chrono::high_resolution_clock::now();
        *mobile_encrypt_ms = std::chrono::duration_cast<std::chrono::duration<double, std::milli>>(
                                 mobile_encrypt_end - mobile_encrypt_start)
                                 .count();
    }

    std::string decrypted;
    bundle.ctdata_verified = DecryptData(session_key, bundle.nonce, bundle.ctdata, bundle.auth_tag, decrypted) &&
                             decrypted == plaintext;
    if (!bundle.ctdata_verified) {
        throw std::runtime_error("ChaCha20-Poly1305 round-trip verification failed");
    }
    bundle.secure_index = BuildSecureIndex(params, bundle.keyword_set, bundle.file_nonce);
}

bool SaveCiphertextBundle(const SystemParams& params, const CiphertextBundle& bundle, const std::string& path) {
    std::ofstream out(path, std::ios::binary);
    if (!out.is_open()) {
        return false;
    }

    const std::string magic = "PQABSE_BUNDLE_V7";
    if (!WriteString(out, magic) || !WriteString(out, bundle.bundle_label) ||
        !WriteByteVector(out, bundle.nonce) || !WriteByteVector(out, bundle.ctdata) ||
        !WriteByteVector(out, bundle.auth_tag) || !WriteLogicalPolicy(out, bundle.logical_policy) ||
        !WritePolicy(out, bundle.policy) || !WriteString(out, bundle.version_tag) ||
        !WriteKeywordSet(out, bundle.keyword_set) || !WritePolicy(out, bundle.ctk.policy) ||
        !WriteElement(out, bundle.ctk.header_u) || !WriteElement(out, bundle.ctk.policy_tag) ||
        !WriteString(out, bundle.ctk.reencryption_tag) || !WriteElement(out, bundle.ctk.epoch_tag)) {
        return false;
    }
    out.write(reinterpret_cast<const char*>(bundle.ctk.update_seed_commitment.data()),
              static_cast<std::streamsize>(bundle.ctk.update_seed_commitment.size()));
    if (!out) {
        return false;
    }

    out.write(reinterpret_cast<const char*>(bundle.file_nonce.data()),
              static_cast<std::streamsize>(bundle.file_nonce.size()));
    out.write(reinterpret_cast<const char*>(&bundle.ctdata_verified), sizeof(bundle.ctdata_verified));
    out.write(reinterpret_cast<const char*>(bundle.ctk.encrypted_session_key.data()),
              static_cast<std::streamsize>(bundle.ctk.encrypted_session_key.size()));
    if (!out) {
        return false;
    }

    const uint64_t iw_count = static_cast<uint64_t>(bundle.secure_index.size());
    out.write(reinterpret_cast<const char*>(&iw_count), sizeof(iw_count));
    if (!out) {
        return false;
    }
    for (const auto& entry : bundle.secure_index) {
        if (!WriteElement(out, entry)) {
            return false;
        }
    }

    const uint64_t ring_dim = params.ring_dim;
    out.write(reinterpret_cast<const char*>(&ring_dim), sizeof(ring_dim));
    return static_cast<bool>(out);
}

bool LoadCiphertextBundle(const SystemParams& params, CiphertextBundle& bundle, const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) {
        return false;
    }

    std::string magic;
    if (!ReadString(in, magic) || (magic != "PQABSE_BUNDLE_V3" && magic != "PQABSE_BUNDLE_V4" && magic != "PQABSE_BUNDLE_V5" && magic != "PQABSE_BUNDLE_V6" && magic != "PQABSE_BUNDLE_V7")) {
        return false;
    }
    bundle.keyword_set.clear();
    if (!ReadString(in, bundle.bundle_label) || !ReadByteVector(in, bundle.nonce) ||
        !ReadByteVector(in, bundle.ctdata) || !ReadByteVector(in, bundle.auth_tag) ||
        !ReadLogicalPolicy(in, bundle.logical_policy) || !ReadPolicy(in, bundle.policy) ||
        !ReadString(in, bundle.version_tag) ||
        ((magic == "PQABSE_BUNDLE_V3" || magic == "PQABSE_BUNDLE_V5" || magic == "PQABSE_BUNDLE_V6" || magic == "PQABSE_BUNDLE_V7") && !ReadKeywordSet(in, bundle.keyword_set)) ||
        !ReadPolicy(in, bundle.ctk.policy) || !ReadElement(in, params, bundle.ctk.header_u) ||
        !ReadElement(in, params, bundle.ctk.policy_tag) ||
        ((magic == "PQABSE_BUNDLE_V6" || magic == "PQABSE_BUNDLE_V7") && (!ReadString(in, bundle.ctk.reencryption_tag) || !ReadElement(in, params, bundle.ctk.epoch_tag)))) {
        return false;
    }

    if (magic == "PQABSE_BUNDLE_V7") {
        in.read(reinterpret_cast<char*>(bundle.ctk.update_seed_commitment.data()),
                static_cast<std::streamsize>(bundle.ctk.update_seed_commitment.size()));
        if (!in) {
            return false;
        }
    } else {
        bundle.ctk.update_seed_commitment.fill(0);
        if (magic != "PQABSE_BUNDLE_V6") {
            bundle.ctk.reencryption_tag.clear();
            bundle.ctk.epoch_tag = MakeCoefficientElement(params);
        }
    }

    in.read(reinterpret_cast<char*>(bundle.file_nonce.data()), static_cast<std::streamsize>(bundle.file_nonce.size()));
    in.read(reinterpret_cast<char*>(&bundle.ctdata_verified), sizeof(bundle.ctdata_verified));
    in.read(reinterpret_cast<char*>(bundle.ctk.encrypted_session_key.data()),
            static_cast<std::streamsize>(bundle.ctk.encrypted_session_key.size()));
    if (!in) {
        return false;
    }

    uint64_t iw_count = 0;
    in.read(reinterpret_cast<char*>(&iw_count), sizeof(iw_count));
    if (!in) {
        return false;
    }
    bundle.secure_index.clear();
    bundle.secure_index.reserve(static_cast<size_t>(iw_count));
    for (uint64_t i = 0; i < iw_count; ++i) {
        TrapdoorElement entry;
        if (!ReadElement(in, params, entry)) {
            return false;
        }
        bundle.secure_index.push_back(std::move(entry));
    }

    uint64_t ring_dim = 0;
    in.read(reinterpret_cast<char*>(&ring_dim), sizeof(ring_dim));
    return static_cast<bool>(in) && ring_dim == params.ring_dim;
}




