#include "phase4_search.h"

#include <algorithm>
#include <fstream>
#include <set>
#include <sstream>

namespace {

std::vector<std::string> CanonicalizeStrings(const std::vector<std::string>& values) {
    std::vector<std::string> canonical = values;
    std::sort(canonical.begin(), canonical.end());
    canonical.erase(std::unique(canonical.begin(), canonical.end()), canonical.end());
    return canonical;
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

bool ElementsEqual(TrapdoorElement lhs, TrapdoorElement rhs) {
    lhs.SetFormat(Format::COEFFICIENT);
    rhs.SetFormat(Format::COEFFICIENT);
    return lhs == rhs;
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
    if (!in) {
        return false;
    }
    target = MakeCoefficientElement(params);
    target.SetValuesToZero();
    if (length != target.GetLength()) {
        return false;
    }
    for (uint32_t i = 0; i < target.GetLength(); ++i) {
        uint64_t coefficient = 0;
        in.read(reinterpret_cast<char*>(&coefficient), sizeof(coefficient));
        if (!in) {
            return false;
        }
        target[i] = TrapdoorElement::Integer(coefficient);
    }
    target.SetFormat(Format::COEFFICIENT);
    return true;
}

}  // namespace

void TrapGen(const SystemParams& params, const UserSecretKey& user_sk, const std::array<unsigned char, 16>& file_nonce,
             const std::string& label, const std::vector<std::string>& query_keywords, SearchTrapdoor& trapdoor) {
    trapdoor.label = label;
    trapdoor.gid = user_sk.gid;
    trapdoor.query_keywords = CanonicalizeStrings(query_keywords);
    trapdoor.user_binding = user_sk.target_u;
    trapdoor.keyword_tokens.clear();
    trapdoor.keyword_tokens.reserve(trapdoor.query_keywords.size());
    for (const auto& keyword : trapdoor.query_keywords) {
        trapdoor.keyword_tokens.push_back(EncodeKeywordToken(params, keyword, file_nonce));
    }
}

bool Match(const CiphertextBundle& bundle, const SearchTrapdoor& trapdoor, std::vector<std::string>& matched_keywords) {
    matched_keywords.clear();
    for (size_t i = 0; i < trapdoor.keyword_tokens.size(); ++i) {
        bool found = false;
        for (const auto& entry : bundle.secure_index) {
            if (ElementsEqual(trapdoor.keyword_tokens[i], entry)) {
                found = true;
                break;
            }
        }
        if (!found) {
            matched_keywords.clear();
            return false;
        }
        matched_keywords.push_back(trapdoor.query_keywords[i]);
    }
    return true;
}

std::size_t CountKeywordMatches(const CiphertextBundle& bundle, const SearchTrapdoor& trapdoor,
                                std::vector<std::string>& matched_keywords) {
    matched_keywords.clear();
    for (size_t i = 0; i < trapdoor.keyword_tokens.size(); ++i) {
        for (const auto& entry : bundle.secure_index) {
            if (ElementsEqual(trapdoor.keyword_tokens[i], entry)) {
                matched_keywords.push_back(trapdoor.query_keywords[i]);
                break;
            }
        }
    }
    return matched_keywords.size();
}

bool MatchAtLeast(const CiphertextBundle& bundle, const SearchTrapdoor& trapdoor, std::size_t min_match_count,
                  std::vector<std::string>& matched_keywords) {
    if (min_match_count == 0) {
        matched_keywords.clear();
        return true;
    }
    return CountKeywordMatches(bundle, trapdoor, matched_keywords) >= min_match_count;
}

bool RetrieveAndDecrypt(const SystemParams& params, const UserSecretKey& user_sk, const CiphertextBundle& bundle,
                        const SearchTrapdoor& trapdoor, SearchResult& result) {
    result = {};
    result.keyword_match = Match(bundle, trapdoor, result.matched_keywords);
    if (!result.keyword_match) {
        return false;
    }

    result.policy_satisfied = PolicySatisfied(user_sk.attributes, bundle.logical_policy);
    if (!result.policy_satisfied) {
        return false;
    }

    std::array<unsigned char, 32> session_key{};
    result.session_key_recovered = DecABSE(params, user_sk, bundle.logical_policy, bundle.ctk, session_key);
    if (!result.session_key_recovered) {
        return false;
    }

    result.plaintext_recovered = DecryptData(session_key, bundle.nonce, bundle.ctdata, bundle.auth_tag, result.plaintext);
    return result.plaintext_recovered;
}

bool SaveSearchTrapdoor(const SystemParams& params, const SearchTrapdoor& trapdoor, const std::string& path) {
    std::ofstream out(path, std::ios::binary);
    if (!out.is_open()) {
        return false;
    }

    const std::string magic = "PQABSE_TRAPDOOR_V1";
    if (!WriteString(out, magic) || !WriteString(out, trapdoor.label) || !WriteString(out, trapdoor.gid)) {
        return false;
    }

    const uint64_t keyword_count = static_cast<uint64_t>(trapdoor.query_keywords.size());
    out.write(reinterpret_cast<const char*>(&keyword_count), sizeof(keyword_count));
    if (!out) {
        return false;
    }
    for (size_t i = 0; i < trapdoor.query_keywords.size(); ++i) {
        if (!WriteString(out, trapdoor.query_keywords[i]) || !WriteElement(out, trapdoor.keyword_tokens[i])) {
            return false;
        }
    }

    if (!WriteElement(out, trapdoor.user_binding)) {
        return false;
    }

    const uint64_t ring_dim = params.ring_dim;
    out.write(reinterpret_cast<const char*>(&ring_dim), sizeof(ring_dim));
    return static_cast<bool>(out);
}

bool LoadSearchTrapdoor(const SystemParams& params, SearchTrapdoor& trapdoor, const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) {
        return false;
    }

    std::string magic;
    if (!ReadString(in, magic) || magic != "PQABSE_TRAPDOOR_V1") {
        return false;
    }
    if (!ReadString(in, trapdoor.label) || !ReadString(in, trapdoor.gid)) {
        return false;
    }

    uint64_t keyword_count = 0;
    in.read(reinterpret_cast<char*>(&keyword_count), sizeof(keyword_count));
    if (!in) {
        return false;
    }
    trapdoor.query_keywords.clear();
    trapdoor.keyword_tokens.clear();
    trapdoor.query_keywords.reserve(static_cast<size_t>(keyword_count));
    trapdoor.keyword_tokens.reserve(static_cast<size_t>(keyword_count));
    for (uint64_t i = 0; i < keyword_count; ++i) {
        std::string keyword;
        TrapdoorElement token;
        if (!ReadString(in, keyword) || !ReadElement(in, params, token)) {
            return false;
        }
        trapdoor.query_keywords.push_back(std::move(keyword));
        trapdoor.keyword_tokens.push_back(std::move(token));
    }

    if (!ReadElement(in, params, trapdoor.user_binding)) {
        return false;
    }

    uint64_t ring_dim = 0;
    in.read(reinterpret_cast<char*>(&ring_dim), sizeof(ring_dim));
    return static_cast<bool>(in) && ring_dim == params.ring_dim;
}
