#include <jni.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <fstream>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#if PQABSE_PREBUILT_AVAILABLE
#include <openfhe/core/config_core.h>
#include <openfhe/core/lattice/hal/lat-backend.h>
#include <openfhe/core/lattice/trapdoor.h>
#include <oqs/oqsconfig.h>
#endif

namespace {

std::string JStringToStdString(JNIEnv* env, jstring value) {
    if (value == nullptr) {
        return "";
    }
    const char* chars = env->GetStringUTFChars(value, nullptr);
    std::string result = chars ? chars : "";
    if (chars != nullptr) {
        env->ReleaseStringUTFChars(value, chars);
    }
    return result;
}

std::vector<unsigned char> JByteArrayToVector(JNIEnv* env, jbyteArray value) {
    if (value == nullptr) {
        return {};
    }
    const auto length = static_cast<size_t>(env->GetArrayLength(value));
    std::vector<unsigned char> result(length);
    if (length != 0) {
        env->GetByteArrayRegion(
            value,
            0,
            static_cast<jsize>(length),
            reinterpret_cast<jbyte*>(result.data()));
    }
    return result;
}

std::string EscapeJson(const std::string& input) {
    std::ostringstream out;
    for (char ch : input) {
        switch (ch) {
            case '\\':
                out << "\\\\";
                break;
            case '"':
                out << "\\\"";
                break;
            case '\n':
                out << "\\n";
                break;
            case '\r':
                out << "\\r";
                break;
            case '\t':
                out << "\\t";
                break;
            default:
                out << ch;
                break;
        }
    }
    return out.str();
}

std::string BuildRuntimeStatus() {
    std::ostringstream out;
#if PQABSE_PREBUILT_AVAILABLE
    out << "Native crypto prebuilts loaded for ABI " << PQABSE_PREBUILT_ABI
        << ". liboqs=" << OQS_VERSION_TEXT
        << ", OpenFHE math backend=" << MATHBACKEND
        << ", nativeint=" << NATIVEINT
        << ". Prebuilt root: " << PQABSE_PREBUILT_ROOT;
#else
    out << "No Android crypto prebuilts are available for ABI " << PQABSE_PREBUILT_ABI
        << ". Expected root: " << PQABSE_PREBUILT_ROOT
        << ". The app is still running the JNI bridge, but only the arm64-v8a dependency set has been built so far.";
#endif
    return out.str();
}

std::string BuildBlockedArtifactsJson(const std::string& gid,
                                      const std::string& keywordsCsv,
                                      const std::string& registerPayload) {
    std::ostringstream out;
    out << "{";
    out << "\"status\":\"blocked\",";
    out << "\"auth_token_base64\":\"\",";
    out << "\"shortlist_trapdoor_base64\":\"\",";
    out << "\"details\":\""
        << EscapeJson(BuildRuntimeStatus())
        << " Local query artifact generation is still blocked because the repo's auth-token path calls IdentityAuthority::authenticate_user(...), which requires IA-side signing/prover state that the Android app does not have locally yet."
        << " gid=" << EscapeJson(gid)
        << ", keywords=" << EscapeJson(keywordsCsv)
        << ", register_payload_bytes=" << registerPayload.size()
        << "\"";
    out << "}";
    return out.str();
}

std::string BuildDecryptErrorJson(const std::string& reason) {
    std::ostringstream out;
    out << "{";
    out << "\"status\":\"error\",";
    out << "\"message\":\"" << EscapeJson(reason) << "\"";
    out << "}";
    return out.str();
}

#if PQABSE_PREBUILT_AVAILABLE

struct SystemParams {
    uint32_t ring_dim = 0;
    uint64_t modulus = 0;
    double trapdoor_stddev = 0.0;
    int64_t gadget_base = 0;
    bool balanced = false;
    size_t trapdoor_k = 0;
};

using TrapdoorElement = lbcrypto::Poly;
using TrapdoorMatrix = lbcrypto::Matrix<TrapdoorElement>;
using ElementParams = TrapdoorElement::Params;

struct UserSecretKey {
    std::string gid;
    std::vector<std::string> attributes;
    int epoch = 0;
    std::string update_seed;
    TrapdoorElement target_u;
    TrapdoorMatrix preimage;
};

enum class PolicyKind {
    Attribute,
    And,
    Or,
    Threshold,
};

struct LogicalPolicy {
    PolicyKind kind = PolicyKind::Attribute;
    size_t threshold = 0;
    std::string attribute;
    std::vector<LogicalPolicy> children;
};

struct AccessPolicy {
    std::vector<std::vector<int64_t>> matrix;
    std::vector<std::string> rho;
    std::string descriptor;
    bool is_summary = false;
};

struct CiphertextKey {
    TrapdoorElement header_u;
    TrapdoorElement policy_tag;
    TrapdoorElement epoch_tag;
    std::string reencryption_tag;
    std::array<unsigned char, 32> update_seed_commitment{};
    std::array<unsigned char, 32> encrypted_session_key{};
    AccessPolicy policy;
};

struct CiphertextBundle {
    std::string bundle_label;
    std::vector<unsigned char> nonce;
    std::vector<unsigned char> ctdata;
    std::vector<unsigned char> auth_tag;
    CiphertextKey ctk;
    std::vector<TrapdoorElement> secure_index;
    std::vector<std::string> keyword_set;
    std::array<unsigned char, 16> file_nonce{};
    std::string version_tag;
    LogicalPolicy logical_policy;
    AccessPolicy policy;
    bool ctdata_verified = false;
};

struct SearchTrapdoor {
    std::string label;
    std::string gid;
    std::vector<std::string> query_keywords;
    std::vector<TrapdoorElement> keyword_tokens;
    TrapdoorElement user_binding;
};

std::array<unsigned char, 32> Sha256(JNIEnv* env, const std::vector<unsigned char>& input);

std::shared_ptr<ElementParams> BuildElementParams(const SystemParams& params) {
    return std::make_shared<ElementParams>(
        2 * params.ring_dim,
        lbcrypto::BigInteger(std::to_string(params.modulus)));
}

uint64_t CoefficientToUint64(const TrapdoorElement::Integer& coefficient) {
    std::ostringstream out;
    out << coefficient;
    return std::stoull(out.str());
}

TrapdoorElement MakeCoefficientElement(const SystemParams& params) {
    auto elemParams = BuildElementParams(params);
    return TrapdoorElement(elemParams, Format::COEFFICIENT, true);
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

bool ReadLogicalPolicy(std::istream& in, LogicalPolicy& logicalPolicy) {
    uint64_t kind = 0;
    uint64_t threshold = 0;
    uint64_t childCount = 0;
    in.read(reinterpret_cast<char*>(&kind), sizeof(kind));
    in.read(reinterpret_cast<char*>(&threshold), sizeof(threshold));
    if (!in || !ReadString(in, logicalPolicy.attribute)) {
        return false;
    }
    in.read(reinterpret_cast<char*>(&childCount), sizeof(childCount));
    if (!in) {
        return false;
    }
    logicalPolicy.kind = static_cast<PolicyKind>(kind);
    logicalPolicy.threshold = static_cast<size_t>(threshold);
    logicalPolicy.children.resize(static_cast<size_t>(childCount));
    for (auto& child : logicalPolicy.children) {
        if (!ReadLogicalPolicy(in, child)) {
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
    unsigned char isSummary = 0;
    in.read(reinterpret_cast<char*>(&isSummary), sizeof(isSummary));
    if (!in) {
        return false;
    }
    policy.is_summary = isSummary != 0;
    policy.matrix.clear();
    policy.matrix.reserve(static_cast<size_t>(rows));
    for (uint64_t row = 0; row < rows; ++row) {
        uint64_t cols = 0;
        in.read(reinterpret_cast<char*>(&cols), sizeof(cols));
        if (!in) {
            return false;
        }
        std::vector<int64_t> rowValues(static_cast<size_t>(cols));
        for (uint64_t col = 0; col < cols; ++col) {
            in.read(reinterpret_cast<char*>(&rowValues[col]), sizeof(rowValues[col]));
            if (!in) {
                return false;
            }
        }
        policy.matrix.push_back(std::move(rowValues));
    }
    uint64_t rhoCount = 0;
    in.read(reinterpret_cast<char*>(&rhoCount), sizeof(rhoCount));
    if (!in) {
        return false;
    }
    policy.rho.clear();
    policy.rho.reserve(static_cast<size_t>(rhoCount));
    for (uint64_t i = 0; i < rhoCount; ++i) {
        std::string label;
        if (!ReadString(in, label)) {
            return false;
        }
        policy.rho.push_back(std::move(label));
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

bool ReadMatrix(std::istream& in, const SystemParams& params, TrapdoorMatrix& matrix) {
    uint64_t rows = 0;
    uint64_t cols = 0;
    in.read(reinterpret_cast<char*>(&rows), sizeof(rows));
    in.read(reinterpret_cast<char*>(&cols), sizeof(cols));
    if (!in) {
        return false;
    }
    auto elemParams = BuildElementParams(params);
    matrix = TrapdoorMatrix(
        TrapdoorElement::Allocator(elemParams, Format::EVALUATION),
        static_cast<uint32_t>(rows),
        static_cast<uint32_t>(cols));
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

std::vector<std::string> SplitCsv(const std::string& csv) {
    std::vector<std::string> values;
    std::istringstream in(csv);
    std::string current;
    while (std::getline(in, current, ',')) {
        const auto start = current.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) {
            continue;
        }
        const auto end = current.find_last_not_of(" \t\r\n");
        values.push_back(current.substr(start, end - start + 1));
    }
    return values;
}

std::vector<std::string> CanonicalizeStrings(const std::vector<std::string>& values) {
    std::vector<std::string> canonical = values;
    std::sort(canonical.begin(), canonical.end());
    canonical.erase(std::unique(canonical.begin(), canonical.end()), canonical.end());
    return canonical;
}

void MixHash(JNIEnv* env, const std::vector<unsigned char>& seed, uint32_t index, unsigned char digest[32]) {
    std::vector<unsigned char> input = seed;
    input.push_back(static_cast<unsigned char>((index >> 24) & 0xFF));
    input.push_back(static_cast<unsigned char>((index >> 16) & 0xFF));
    input.push_back(static_cast<unsigned char>((index >> 8) & 0xFF));
    input.push_back(static_cast<unsigned char>(index & 0xFF));
    const auto digestBytes = Sha256(env, input);
    std::copy(digestBytes.begin(), digestBytes.end(), digest);
}

TrapdoorElement SampleUniformElement(JNIEnv* env,
                                     const SystemParams& params,
                                     const std::vector<unsigned char>& seed,
                                     uint32_t offset) {
    TrapdoorElement element = MakeCoefficientElement(params);
    unsigned char digest[32];
    for (uint32_t i = 0; i < params.ring_dim; ++i) {
        MixHash(env, seed, offset + i, digest);
        uint64_t value = 0;
        for (int j = 0; j < 8; ++j) {
            value = (value << 8) | digest[j];
        }
        element[i] = TrapdoorElement::Integer(value % params.modulus);
    }
    element.SetFormat(Format::EVALUATION);
    return element;
}

TrapdoorElement EncodeKeywordToken(JNIEnv* env,
                                   const SystemParams& params,
                                   const std::string& keyword,
                                   const std::array<unsigned char, 16>& fileNonce) {
    (void)fileNonce;
    std::vector<unsigned char> seed = {
        static_cast<unsigned char>('K'),
        static_cast<unsigned char>('W'),
        0
    };
    seed.insert(seed.end(), keyword.begin(), keyword.end());
    return SampleUniformElement(env, params, seed, 0);
}

bool WriteStringBinary(std::ostream& out, const std::string& value) {
    const uint64_t size = static_cast<uint64_t>(value.size());
    out.write(reinterpret_cast<const char*>(&size), sizeof(size));
    out.write(value.data(), static_cast<std::streamsize>(value.size()));
    return static_cast<bool>(out);
}

bool WriteElementBinary(std::ostream& out, const TrapdoorElement& source) {
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

bool SerializeSearchTrapdoor(JNIEnv* env,
                             const SystemParams& params,
                             const UserSecretKey& userKey,
                             const std::string& preferredLabel,
                             const std::vector<std::string>& queryKeywords,
                             std::vector<unsigned char>& output) {
    std::ostringstream out(std::ios::binary);
    const std::string magic = "PQABSE_TRAPDOOR_V1";
    if (!WriteStringBinary(out, magic) ||
        !WriteStringBinary(out, preferredLabel) ||
        !WriteStringBinary(out, userKey.gid)) {
        return false;
    }

    const auto canonicalKeywords = CanonicalizeStrings(queryKeywords);
    const uint64_t keywordCount = static_cast<uint64_t>(canonicalKeywords.size());
    out.write(reinterpret_cast<const char*>(&keywordCount), sizeof(keywordCount));
    if (!out) {
        return false;
    }

    std::array<unsigned char, 16> globalNonce{};
    for (const auto& keyword : canonicalKeywords) {
        if (!WriteStringBinary(out, keyword) ||
            !WriteElementBinary(out, EncodeKeywordToken(env, params, keyword, globalNonce))) {
            return false;
        }
    }

    if (!WriteElementBinary(out, userKey.target_u)) {
        return false;
    }

    const uint64_t ringDim = params.ring_dim;
    out.write(reinterpret_cast<const char*>(&ringDim), sizeof(ringDim));
    if (!out) {
        return false;
    }

    const std::string payload = out.str();
    output.assign(payload.begin(), payload.end());
    return true;
}

bool ParseParamsText(const std::vector<unsigned char>& paramsBytes, SystemParams& params) {
    std::string text(paramsBytes.begin(), paramsBytes.end());
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) {
        const auto pos = line.find('=');
        if (pos == std::string::npos) {
            continue;
        }
        const auto key = line.substr(0, pos);
        const auto value = line.substr(pos + 1);
        if (key == "ring_dim") {
            params.ring_dim = static_cast<uint32_t>(std::stoul(value));
        } else if (key == "modulus") {
            params.modulus = std::stoull(value);
        } else if (key == "trapdoor_stddev") {
            params.trapdoor_stddev = std::stod(value);
        } else if (key == "gadget_base") {
            params.gadget_base = std::stoll(value);
        } else if (key == "balanced") {
            params.balanced = std::stoi(value) != 0;
        } else if (key == "trapdoor_k") {
            params.trapdoor_k = static_cast<size_t>(std::stoull(value));
        }
    }
    return params.ring_dim != 0 && params.modulus != 0 && params.gadget_base > 1;
}

bool LoadUserSecretKeyBytes(const SystemParams& params,
                            const std::vector<unsigned char>& bytes,
                            UserSecretKey& userKey) {
    std::string payload(bytes.begin(), bytes.end());
    std::istringstream in(payload, std::ios::binary);
    std::string magic;
    if (!ReadString(in, magic) || (magic != "PQABSE_USERKEY_V1" && magic != "PQABSE_USERKEY_V2")) {
        return false;
    }
    if (!ReadString(in, userKey.gid) || !ReadStringVector(in, userKey.attributes)) {
        return false;
    }
    if (magic == "PQABSE_USERKEY_V2") {
        in.read(reinterpret_cast<char*>(&userKey.epoch), sizeof(userKey.epoch));
        if (!in || !ReadString(in, userKey.update_seed)) {
            return false;
        }
    } else {
        userKey.epoch = 0;
        userKey.update_seed.clear();
    }
    if (!ReadElement(in, params, userKey.target_u) || !ReadMatrix(in, params, userKey.preimage)) {
        return false;
    }
    uint64_t ringDim = 0;
    in.read(reinterpret_cast<char*>(&ringDim), sizeof(ringDim));
    return static_cast<bool>(in) && ringDim == params.ring_dim;
}

bool LoadSearchTrapdoorBytes(const SystemParams& params,
                             const std::vector<unsigned char>& bytes,
                             SearchTrapdoor& trapdoor) {
    std::string payload(bytes.begin(), bytes.end());
    std::istringstream in(payload, std::ios::binary);
    std::string magic;
    if (!ReadString(in, magic) || magic != "PQABSE_TRAPDOOR_V1") {
        return false;
    }
    if (!ReadString(in, trapdoor.label) || !ReadString(in, trapdoor.gid)) {
        return false;
    }
    uint64_t keywordCount = 0;
    in.read(reinterpret_cast<char*>(&keywordCount), sizeof(keywordCount));
    if (!in) {
        return false;
    }
    trapdoor.query_keywords.clear();
    trapdoor.keyword_tokens.clear();
    trapdoor.query_keywords.reserve(static_cast<size_t>(keywordCount));
    trapdoor.keyword_tokens.reserve(static_cast<size_t>(keywordCount));
    for (uint64_t i = 0; i < keywordCount; ++i) {
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
    uint64_t ringDim = 0;
    in.read(reinterpret_cast<char*>(&ringDim), sizeof(ringDim));
    return static_cast<bool>(in) && ringDim == params.ring_dim;
}

bool LoadCiphertextBundleBytes(const SystemParams& params,
                               const std::vector<unsigned char>& bytes,
                               CiphertextBundle& bundle) {
    std::string payload(bytes.begin(), bytes.end());
    std::istringstream in(payload, std::ios::binary);
    std::string magic;
    if (!ReadString(in, magic) ||
        (magic != "PQABSE_BUNDLE_V3" && magic != "PQABSE_BUNDLE_V4" && magic != "PQABSE_BUNDLE_V5" &&
         magic != "PQABSE_BUNDLE_V6" && magic != "PQABSE_BUNDLE_V7")) {
        return false;
    }
    bundle.keyword_set.clear();
    if (!ReadString(in, bundle.bundle_label) ||
        !ReadByteVector(in, bundle.nonce) ||
        !ReadByteVector(in, bundle.ctdata) ||
        !ReadByteVector(in, bundle.auth_tag) ||
        !ReadLogicalPolicy(in, bundle.logical_policy) ||
        !ReadPolicy(in, bundle.policy) ||
        !ReadString(in, bundle.version_tag) ||
        ((magic == "PQABSE_BUNDLE_V3" || magic == "PQABSE_BUNDLE_V5" || magic == "PQABSE_BUNDLE_V6" ||
          magic == "PQABSE_BUNDLE_V7") &&
         !ReadKeywordSet(in, bundle.keyword_set)) ||
        !ReadPolicy(in, bundle.ctk.policy) ||
        !ReadElement(in, params, bundle.ctk.header_u) ||
        !ReadElement(in, params, bundle.ctk.policy_tag) ||
        ((magic == "PQABSE_BUNDLE_V6" || magic == "PQABSE_BUNDLE_V7") &&
         (!ReadString(in, bundle.ctk.reencryption_tag) || !ReadElement(in, params, bundle.ctk.epoch_tag)))) {
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
    uint64_t secureIndexCount = 0;
    in.read(reinterpret_cast<char*>(&secureIndexCount), sizeof(secureIndexCount));
    if (!in) {
        return false;
    }
    bundle.secure_index.clear();
    bundle.secure_index.reserve(static_cast<size_t>(secureIndexCount));
    for (uint64_t i = 0; i < secureIndexCount; ++i) {
        TrapdoorElement entry;
        if (!ReadElement(in, params, entry)) {
            return false;
        }
        bundle.secure_index.push_back(std::move(entry));
    }
    uint64_t ringDim = 0;
    in.read(reinterpret_cast<char*>(&ringDim), sizeof(ringDim));
    return static_cast<bool>(in) && ringDim == params.ring_dim;
}

std::array<unsigned char, 32> Sha256(JNIEnv* env, const std::vector<unsigned char>& input) {
    jclass mdClass = env->FindClass("java/security/MessageDigest");
    jmethodID getInstance = env->GetStaticMethodID(
        mdClass,
        "getInstance",
        "(Ljava/lang/String;)Ljava/security/MessageDigest;");
    jstring algo = env->NewStringUTF("SHA-256");
    jobject md = env->CallStaticObjectMethod(mdClass, getInstance, algo);
    env->DeleteLocalRef(algo);

    jbyteArray inputArray = env->NewByteArray(static_cast<jsize>(input.size()));
    if (!input.empty()) {
        env->SetByteArrayRegion(
            inputArray,
            0,
            static_cast<jsize>(input.size()),
            reinterpret_cast<const jbyte*>(input.data()));
    }
    jmethodID digestMethod = env->GetMethodID(mdClass, "digest", "([B)[B");
    auto digestArray = static_cast<jbyteArray>(env->CallObjectMethod(md, digestMethod, inputArray));
    std::array<unsigned char, 32> digest{};
    if (digestArray != nullptr && env->GetArrayLength(digestArray) == 32) {
        env->GetByteArrayRegion(digestArray, 0, 32, reinterpret_cast<jbyte*>(digest.data()));
    }
    env->DeleteLocalRef(inputArray);
    if (digestArray != nullptr) {
        env->DeleteLocalRef(digestArray);
    }
    env->DeleteLocalRef(md);
    env->DeleteLocalRef(mdClass);
    return digest;
}

std::array<unsigned char, 32> HashUpdateMaterial(JNIEnv* env, const std::string& updateMaterial) {
    if (updateMaterial.empty()) {
        return {};
    }
    return Sha256(env, std::vector<unsigned char>(updateMaterial.begin(), updateMaterial.end()));
}

bool IsZeroCommitment(const std::array<unsigned char, 32>& commitment) {
    return std::all_of(commitment.begin(), commitment.end(), [](unsigned char value) { return value == 0; });
}

std::array<unsigned char, 32> DeriveMask(JNIEnv* env,
                                         const TrapdoorElement& header,
                                         const TrapdoorElement& policyTag,
                                         const TrapdoorElement* epochTag = nullptr,
                                         const std::string& reencryptionTag = "",
                                         const std::array<unsigned char, 32>* updateSeedCommitment = nullptr) {
    TrapdoorElement headerCopy = header;
    TrapdoorElement policyCopy = policyTag;
    headerCopy.SetFormat(Format::COEFFICIENT);
    policyCopy.SetFormat(Format::COEFFICIENT);

    std::vector<unsigned char> input;
    input.reserve(static_cast<size_t>(headerCopy.GetLength() + policyCopy.GetLength()) * 2 + 128);
    for (uint32_t i = 0; i < headerCopy.GetLength(); ++i) {
        const uint64_t value = CoefficientToUint64(headerCopy[i]);
        input.push_back(static_cast<unsigned char>(value & 0xFF));
        input.push_back(static_cast<unsigned char>((value >> 8) & 0xFF));
    }
    for (uint32_t i = 0; i < policyCopy.GetLength(); ++i) {
        const uint64_t value = CoefficientToUint64(policyCopy[i]);
        input.push_back(static_cast<unsigned char>(value & 0xFF));
        input.push_back(static_cast<unsigned char>((value >> 8) & 0xFF));
    }
    if (!reencryptionTag.empty() && epochTag != nullptr) {
        TrapdoorElement epochCopy = *epochTag;
        epochCopy.SetFormat(Format::COEFFICIENT);
        for (uint32_t i = 0; i < epochCopy.GetLength(); ++i) {
            const uint64_t value = CoefficientToUint64(epochCopy[i]);
            input.push_back(static_cast<unsigned char>(value & 0xFF));
            input.push_back(static_cast<unsigned char>((value >> 8) & 0xFF));
        }
        input.insert(input.end(), reencryptionTag.begin(), reencryptionTag.end());
    }
    if (updateSeedCommitment != nullptr && !IsZeroCommitment(*updateSeedCommitment)) {
        input.insert(input.end(), updateSeedCommitment->begin(), updateSeedCommitment->end());
    }
    return Sha256(env, input);
}

bool ElementsEqual(TrapdoorElement lhs, TrapdoorElement rhs) {
    lhs.SetFormat(Format::COEFFICIENT);
    rhs.SetFormat(Format::COEFFICIENT);
    return lhs == rhs;
}

bool Match(const CiphertextBundle& bundle,
           const SearchTrapdoor& trapdoor,
           std::vector<std::string>& matchedKeywords) {
    matchedKeywords.clear();
    for (size_t i = 0; i < trapdoor.keyword_tokens.size(); ++i) {
        bool found = false;
        for (const auto& entry : bundle.secure_index) {
            if (ElementsEqual(trapdoor.keyword_tokens[i], entry)) {
                found = true;
                break;
            }
        }
        if (!found) {
            matchedKeywords.clear();
            return false;
        }
        matchedKeywords.push_back(trapdoor.query_keywords[i]);
    }
    return true;
}

size_t CountKeywordMatches(const CiphertextBundle& bundle,
                           const SearchTrapdoor& trapdoor,
                           std::vector<std::string>& matchedKeywords) {
    matchedKeywords.clear();
    for (size_t i = 0; i < trapdoor.keyword_tokens.size(); ++i) {
        for (const auto& entry : bundle.secure_index) {
            if (ElementsEqual(trapdoor.keyword_tokens[i], entry)) {
                matchedKeywords.push_back(trapdoor.query_keywords[i]);
                break;
            }
        }
    }
    return matchedKeywords.size();
}

size_t DefaultMinMatchCount(const SearchTrapdoor& trapdoor) {
    if (trapdoor.query_keywords.empty()) {
        return 0;
    }
    if (trapdoor.query_keywords.size() < 3) {
        return 1;
    }
    return 2;
}

bool MatchAtLeast(const CiphertextBundle& bundle,
                  const SearchTrapdoor& trapdoor,
                  size_t minMatchCount,
                  std::vector<std::string>& matchedKeywords) {
    if (minMatchCount == 0) {
        matchedKeywords.clear();
        return true;
    }
    return CountKeywordMatches(bundle, trapdoor, matchedKeywords) >= minMatchCount;
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
            size_t satisfied = 0;
            for (const auto& child : policy.children) {
                if (EvaluatePolicy(attributes, child)) {
                    ++satisfied;
                }
            }
            return satisfied >= policy.threshold;
        }
    }
    return false;
}

bool PolicySatisfied(const std::vector<std::string>& userAttributes, const LogicalPolicy& logicalPolicy) {
    return EvaluatePolicy(std::set<std::string>(userAttributes.begin(), userAttributes.end()), logicalPolicy);
}

std::string Base64Encode(const std::vector<unsigned char>& bytes) {
    static const char* alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string output;
    output.reserve(((bytes.size() + 2) / 3) * 4);
    size_t index = 0;
    while (index + 3 <= bytes.size()) {
        const uint32_t block = (static_cast<uint32_t>(bytes[index]) << 16) |
                               (static_cast<uint32_t>(bytes[index + 1]) << 8) |
                               static_cast<uint32_t>(bytes[index + 2]);
        output.push_back(alphabet[(block >> 18) & 0x3F]);
        output.push_back(alphabet[(block >> 12) & 0x3F]);
        output.push_back(alphabet[(block >> 6) & 0x3F]);
        output.push_back(alphabet[block & 0x3F]);
        index += 3;
    }
    const size_t remaining = bytes.size() - index;
    if (remaining == 1) {
        const uint32_t block = static_cast<uint32_t>(bytes[index]) << 16;
        output.push_back(alphabet[(block >> 18) & 0x3F]);
        output.push_back(alphabet[(block >> 12) & 0x3F]);
        output.push_back('=');
        output.push_back('=');
    } else if (remaining == 2) {
        const uint32_t block = (static_cast<uint32_t>(bytes[index]) << 16) |
                               (static_cast<uint32_t>(bytes[index + 1]) << 8);
        output.push_back(alphabet[(block >> 18) & 0x3F]);
        output.push_back(alphabet[(block >> 12) & 0x3F]);
        output.push_back(alphabet[(block >> 6) & 0x3F]);
        output.push_back('=');
    }
    return output;
}

std::string BuildTrapdoorOkJson(const std::vector<unsigned char>& trapdoorBytes) {
    std::ostringstream out;
    out << "{";
    out << "\"status\":\"ok\",";
    out << "\"shortlist_trapdoor_base64\":\"" << Base64Encode(trapdoorBytes) << "\"";
    out << "}";
    return out.str();
}

std::string BuildDecryptOkJson(const CiphertextBundle& bundle,
                               const std::vector<std::string>& matchedKeywords,
                               const std::array<unsigned char, 32>& sessionKey) {
    std::ostringstream out;
    out << "{";
    out << "\"status\":\"ok\",";
    out << "\"bundle_label\":\"" << EscapeJson(bundle.bundle_label) << "\",";
    out << "\"session_key_base64\":\""
        << Base64Encode(std::vector<unsigned char>(sessionKey.begin(), sessionKey.end()))
        << "\",";
    out << "\"nonce_base64\":\"" << Base64Encode(bundle.nonce) << "\",";
    out << "\"ciphertext_base64\":\"" << Base64Encode(bundle.ctdata) << "\",";
    out << "\"auth_tag_base64\":\"" << Base64Encode(bundle.auth_tag) << "\",";
    out << "\"matched_keywords\":[";
    for (size_t i = 0; i < matchedKeywords.size(); ++i) {
        if (i != 0) {
            out << ",";
        }
        out << "\"" << EscapeJson(matchedKeywords[i]) << "\"";
    }
    out << "]";
    out << "}";
    return out.str();
}

#endif

}  // namespace

extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_pqabse_1srmmobilehttp_NativeBridge_getBridgeStatus(JNIEnv* env, jobject /* thiz */) {
    const std::string message = BuildRuntimeStatus();
    return env->NewStringUTF(message.c_str());
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_pqabse_1srmmobilehttp_NativeBridge_generateQueryArtifacts(
    JNIEnv* env,
    jobject /* thiz */,
    jstring register_response_json,
    jstring gid,
    jstring keywords_csv) {
    const std::string registerPayload = JStringToStdString(env, register_response_json);
    const std::string gidValue = JStringToStdString(env, gid);
    const std::string keywordsValue = JStringToStdString(env, keywords_csv);
    const std::string json = BuildBlockedArtifactsJson(gidValue, keywordsValue, registerPayload);
    return env->NewStringUTF(json.c_str());
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_pqabse_1srmmobilehttp_NativeBridge_generateShortlistTrapdoor(
    JNIEnv* env,
    jobject /* thiz */,
    jbyteArray phase1_params_bytes,
    jbyteArray user_key_bytes,
    jstring preferred_label,
    jstring keywords_csv) {
#if !PQABSE_PREBUILT_AVAILABLE
    const std::string message = BuildDecryptErrorJson(
        BuildRuntimeStatus() + " Local trapdoor generation cannot start because no native crypto prebuilts are loaded.");
    return env->NewStringUTF(message.c_str());
#else
    try {
        const auto paramsBytes = JByteArrayToVector(env, phase1_params_bytes);
        const auto userKeyBytes = JByteArrayToVector(env, user_key_bytes);
        const std::string preferredLabel = JStringToStdString(env, preferred_label);
        const std::string keywordsCsv = JStringToStdString(env, keywords_csv);

        SystemParams params{};
        if (!ParseParamsText(paramsBytes, params)) {
            const std::string error = BuildDecryptErrorJson("Failed to parse Phase 1 parameters");
            return env->NewStringUTF(error.c_str());
        }

        UserSecretKey userKey;
        if (!LoadUserSecretKeyBytes(params, userKeyBytes, userKey)) {
            const std::string error = BuildDecryptErrorJson("Failed to load user secret key");
            return env->NewStringUTF(error.c_str());
        }

        const auto queryKeywords = SplitCsv(keywordsCsv);
        if (queryKeywords.empty()) {
            const std::string error = BuildDecryptErrorJson("No query keywords provided");
            return env->NewStringUTF(error.c_str());
        }

        std::vector<unsigned char> trapdoorBytes;
        if (!SerializeSearchTrapdoor(env, params, userKey, preferredLabel, queryKeywords, trapdoorBytes)) {
            const std::string error = BuildDecryptErrorJson("Failed to serialize shortlist trapdoor");
            return env->NewStringUTF(error.c_str());
        }

        const std::string okJson = BuildTrapdoorOkJson(trapdoorBytes);
        return env->NewStringUTF(okJson.c_str());
    } catch (const std::exception& exc) {
        const std::string error = BuildDecryptErrorJson(std::string("Native trapdoor exception: ") + exc.what());
        return env->NewStringUTF(error.c_str());
    }
#endif
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_pqabse_1srmmobilehttp_NativeBridge_decryptLatestQueryResult(
    JNIEnv* env,
    jobject /* thiz */,
    jbyteArray phase1_params_bytes,
    jbyteArray user_key_bytes,
    jbyteArray shortlist_trapdoor_bytes,
    jbyteArray bundle_bytes) {
#if !PQABSE_PREBUILT_AVAILABLE
    const std::string message = BuildDecryptErrorJson(
        BuildRuntimeStatus() + " Local decrypt cannot start because no native crypto prebuilts are loaded.");
    return env->NewStringUTF(message.c_str());
#else
    try {
        const auto paramsBytes = JByteArrayToVector(env, phase1_params_bytes);
        const auto userKeyBytes = JByteArrayToVector(env, user_key_bytes);
        const auto trapdoorBytes = JByteArrayToVector(env, shortlist_trapdoor_bytes);
        const auto bundleBytes = JByteArrayToVector(env, bundle_bytes);

        SystemParams params{};
        if (!ParseParamsText(paramsBytes, params)) {
            const std::string error = BuildDecryptErrorJson("Failed to parse Phase 1 parameters");
            return env->NewStringUTF(error.c_str());
        }

        UserSecretKey userKey;
        if (!LoadUserSecretKeyBytes(params, userKeyBytes, userKey)) {
            const std::string error = BuildDecryptErrorJson("Failed to load user secret key");
            return env->NewStringUTF(error.c_str());
        }

        SearchTrapdoor trapdoor;
        if (!LoadSearchTrapdoorBytes(params, trapdoorBytes, trapdoor)) {
            const std::string error = BuildDecryptErrorJson("Failed to load shortlist trapdoor");
            return env->NewStringUTF(error.c_str());
        }

        CiphertextBundle bundle;
        if (!LoadCiphertextBundleBytes(params, bundleBytes, bundle)) {
            const std::string error = BuildDecryptErrorJson("Failed to load ciphertext bundle");
            return env->NewStringUTF(error.c_str());
        }

        std::vector<std::string> matchedKeywords;
        const size_t minMatchCount = DefaultMinMatchCount(trapdoor);
        if (!MatchAtLeast(bundle, trapdoor, minMatchCount, matchedKeywords)) {
            const std::string error = BuildDecryptErrorJson(
                "Bundle keywords do not satisfy the shortlist min-match rule");
            return env->NewStringUTF(error.c_str());
        }

        if (!PolicySatisfied(userKey.attributes, bundle.logical_policy)) {
            const std::string error = BuildDecryptErrorJson("User attributes do not satisfy the bundle policy");
            return env->NewStringUTF(error.c_str());
        }

        const auto expectedCommitment = HashUpdateMaterial(env, userKey.update_seed);
        if (bundle.ctk.update_seed_commitment != expectedCommitment) {
            const std::string error = BuildDecryptErrorJson("Update-seed commitment mismatch");
            return env->NewStringUTF(error.c_str());
        }

        const TrapdoorElement* epochTag =
            bundle.ctk.reencryption_tag.empty() ? nullptr : &bundle.ctk.epoch_tag;
        const auto mask = DeriveMask(
            env,
            bundle.ctk.header_u,
            bundle.ctk.policy_tag,
            epochTag,
            bundle.ctk.reencryption_tag,
            &bundle.ctk.update_seed_commitment);

        std::array<unsigned char, 32> sessionKey{};
        for (size_t i = 0; i < sessionKey.size(); ++i) {
            sessionKey[i] = static_cast<unsigned char>(bundle.ctk.encrypted_session_key[i] ^ mask[i]);
        }

        const std::string okJson = BuildDecryptOkJson(bundle, matchedKeywords, sessionKey);
        return env->NewStringUTF(okJson.c_str());
    } catch (const std::exception& exc) {
        const std::string error = BuildDecryptErrorJson(std::string("Native decrypt exception: ") + exc.what());
        return env->NewStringUTF(error.c_str());
    }
#endif
}
