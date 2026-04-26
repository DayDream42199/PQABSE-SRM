#include "entities/SoftwareTee.h"

#include <algorithm>
#include <cctype>
#include <stdexcept>

namespace abse_zkp {
namespace {

class PolicyExpressionParser {
public:
    explicit PolicyExpressionParser(std::string expression) : expression_(std::move(expression)) {}

    LogicalPolicy Parse() {
        const auto policy = ParseExpression();
        SkipWhitespace();
        if (!AtEnd()) {
            throw std::invalid_argument("unexpected trailing input in policy expression: " + expression_.substr(position_));
        }
        return policy;
    }

private:
    bool AtEnd() const {
        return position_ >= expression_.size();
    }

    void SkipWhitespace() {
        while (!AtEnd() && std::isspace(static_cast<unsigned char>(expression_[position_]))) {
            ++position_;
        }
    }

    bool Consume(char expected) {
        SkipWhitespace();
        if (AtEnd() || expression_[position_] != expected) {
            return false;
        }
        ++position_;
        return true;
    }

    void Expect(char expected) {
        if (!Consume(expected)) {
            throw std::invalid_argument(std::string("expected '") + expected + "' in policy expression");
        }
    }

    std::string ParseIdentifier() {
        SkipWhitespace();
        const std::size_t start = position_;
        while (!AtEnd()) {
            const char ch = expression_[position_];
            if (std::isalnum(static_cast<unsigned char>(ch)) || ch == '_' || ch == '-' || ch == ':' || ch == '/') {
                ++position_;
            } else {
                break;
            }
        }
        if (start == position_) {
            throw std::invalid_argument("expected identifier in policy expression");
        }
        return expression_.substr(start, position_ - start);
    }

    std::size_t ParseNumber() {
        SkipWhitespace();
        const std::size_t start = position_;
        while (!AtEnd() && std::isdigit(static_cast<unsigned char>(expression_[position_]))) {
            ++position_;
        }
        if (start == position_) {
            throw std::invalid_argument("expected number in threshold policy");
        }
        return static_cast<std::size_t>(std::stoull(expression_.substr(start, position_ - start)));
    }

    std::vector<LogicalPolicy> ParseExpressionList() {
        std::vector<LogicalPolicy> children;
        do {
            children.push_back(ParseExpression());
            SkipWhitespace();
        } while (Consume(','));
        return children;
    }

    bool TryParseKOfNKeyword(const std::string& keyword, std::size_t& threshold, std::size_t& expected_children) const {
        const auto marker = keyword.find("-OF-");
        if (marker == std::string::npos || marker == 0 || marker + 4 >= keyword.size()) {
            return false;
        }

        const std::string threshold_text = keyword.substr(0, marker);
        const std::string child_count_text = keyword.substr(marker + 4);
        if (!std::all_of(threshold_text.begin(), threshold_text.end(), [](unsigned char ch) { return std::isdigit(ch); }) ||
            !std::all_of(child_count_text.begin(), child_count_text.end(), [](unsigned char ch) { return std::isdigit(ch); })) {
            return false;
        }

        threshold = static_cast<std::size_t>(std::stoull(threshold_text));
        expected_children = static_cast<std::size_t>(std::stoull(child_count_text));
        return true;
    }

    LogicalPolicy ParseExpression() {
        const std::string identifier = ParseIdentifier();
        SkipWhitespace();
        if (!Consume('(')) {
            return MakeAttributePolicy(identifier);
        }

        std::string keyword = identifier;
        for (auto& ch : keyword) {
            ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
        }

        if (keyword == "AND") {
            const auto children = ParseExpressionList();
            Expect(')');
            return MakeAndPolicy(children);
        }
        if (keyword == "OR") {
            const auto children = ParseExpressionList();
            Expect(')');
            return MakeOrPolicy(children);
        }
        if (keyword == "THRESHOLD") {
            const auto threshold = ParseNumber();
            Expect(',');
            const auto children = ParseExpressionList();
            Expect(')');
            return MakeThresholdPolicy(threshold, children);
        }
        std::size_t threshold = 0;
        std::size_t expected_children = 0;
        if (TryParseKOfNKeyword(keyword, threshold, expected_children)) {
            const auto children = ParseExpressionList();
            Expect(')');
            if (children.size() != expected_children) {
                throw std::invalid_argument("threshold policy child count does not match expression");
            }
            return MakeThresholdPolicy(threshold, children);
        }
        if (keyword == "ATTR") {
            const auto child = ParseIdentifier();
            Expect(')');
            return MakeAttributePolicy(child);
        }

        throw std::invalid_argument("unsupported policy operator: " + identifier);
    }

    std::string expression_;
    std::size_t position_ = 0;
};

}  // namespace

void SoftwareTee::GenerateUserKey(const SystemParams& params,
                                  const PK& pk,
                                  const MSK& msk,
                                  const std::string& gid,
                                  const std::vector<std::string>& attributes,
                                  UserSecretKey& user_key,
                                  int epoch,
                                  const std::string& update_seed) const {
    KeyGen(params, pk, msk, gid, attributes, user_key, epoch, update_seed);
}

void SoftwareTee::CreateCiphertextBundle(const SystemParams& params,
                                         const PK& pk,
                                         const std::string& bundle_label,
                                         const std::string& plaintext,
                                         const std::vector<std::string>& keywords,
                                         const LogicalPolicy& logical_policy,
                                         const std::string& version_tag,
                                         CiphertextBundle& bundle) const {
    AssembleCiphertextBundle(params, pk, bundle_label, plaintext, keywords, logical_policy, version_tag, bundle);
}

LogicalPolicy BuildLogicalPolicyFromParts(const std::string& policy_type,
                                          const std::vector<std::string>& policy_attrs,
                                          std::size_t threshold) {
    if (policy_attrs.empty()) throw std::invalid_argument("policy requires at least one attribute");
    if (policy_type == "attribute") {
        if (policy_attrs.size() != 1) throw std::invalid_argument("attribute policy requires exactly one attribute");
        return MakeAttributePolicy(policy_attrs.front());
    }
    if (policy_type == "and") return MakeAndPolicy(policy_attrs);
    if (policy_type == "or") return MakeOrPolicy(policy_attrs);
    if (policy_type == "threshold") {
        if (threshold == 0 || threshold > policy_attrs.size()) throw std::invalid_argument("invalid threshold value");
        return MakeThresholdPolicy(threshold, policy_attrs);
    }
    throw std::invalid_argument("unsupported policy type: " + policy_type);
}

LogicalPolicy BuildLogicalPolicyFromExpression(const std::string& expression) {
    if (expression.empty()) {
        throw std::invalid_argument("policy expression cannot be empty");
    }
    return PolicyExpressionParser(expression).Parse();
}

}  // namespace abse_zkp
