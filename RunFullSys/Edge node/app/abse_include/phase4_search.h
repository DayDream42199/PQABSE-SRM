#ifndef PHASE4_SEARCH_H
#define PHASE4_SEARCH_H

#include "phase2_keygen.h"
#include "phase3_encrypt.h"

#include <string>
#include <vector>

struct SearchTrapdoor {
    std::string label;
    std::string gid;
    std::vector<std::string> query_keywords;
    std::vector<TrapdoorElement> keyword_tokens;
    TrapdoorElement user_binding;
};

struct SearchResult {
    bool keyword_match;
    bool policy_satisfied;
    bool session_key_recovered;
    bool plaintext_recovered;
    std::vector<std::string> matched_keywords;
    std::string plaintext;
};

void TrapGen(const SystemParams& params, const UserSecretKey& user_sk, const std::array<unsigned char, 16>& file_nonce,
             const std::string& label, const std::vector<std::string>& query_keywords, SearchTrapdoor& trapdoor);
bool Match(const CiphertextBundle& bundle, const SearchTrapdoor& trapdoor, std::vector<std::string>& matched_keywords);
bool RetrieveAndDecrypt(const SystemParams& params, const UserSecretKey& user_sk, const CiphertextBundle& bundle,
                        const SearchTrapdoor& trapdoor, SearchResult& result);
bool SaveSearchTrapdoor(const SystemParams& params, const SearchTrapdoor& trapdoor, const std::string& path);
bool LoadSearchTrapdoor(const SystemParams& params, SearchTrapdoor& trapdoor, const std::string& path);

#endif
