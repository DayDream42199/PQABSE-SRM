#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

#include "phase4_search.h"

using namespace std;

namespace {

const string kOutputRoot = "Output";
const string kReadableDir = kOutputRoot + "/Readable";
const string kBinaryDir = kOutputRoot + "/Binary";
const string kBundleSuffix = "_ciphertext_bundle.bin";

struct QueryRequest {
    string label;
    string user_label;
    vector<string> query_keywords;
};

struct QueryHit {
    string bundle_label;
    vector<string> matched_keywords;
    string plaintext;
};

string FormatElementReadable(TrapdoorElement element) {
    element.SetFormat(Format::COEFFICIENT);
    ostringstream out;
    out << '[';
    for (uint32_t i = 0; i < element.GetLength(); ++i) {
        if (i != 0) {
            out << ", ";
        }
        out << element[i];
    }
    out << ']';
    return out.str();
}

bool WriteReadableTrapdoor(const SearchTrapdoor& trapdoor, const string& path) {
    ofstream out(path);
    if (!out.is_open()) {
        return false;
    }
    out << "label=" << trapdoor.label << '\n';
    out << "gid=" << trapdoor.gid << '\n';
    out << "query_keywords=";
    for (size_t i = 0; i < trapdoor.query_keywords.size(); ++i) {
        if (i != 0) {
            out << ',';
        }
        out << trapdoor.query_keywords[i];
    }
    out << "\n\nuser_binding:\n" << FormatElementReadable(trapdoor.user_binding) << "\n\nkeyword_tokens:\n[\n";
    for (size_t i = 0; i < trapdoor.keyword_tokens.size(); ++i) {
        out << "  " << FormatElementReadable(trapdoor.keyword_tokens[i]);
        if (i + 1 != trapdoor.keyword_tokens.size()) {
            out << ',';
        }
        out << '\n';
    }
    out << "]\n";
    return true;
}

bool WriteQuerySummary(const QueryRequest& request, const vector<QueryHit>& hits, const string& path) {
    ofstream out(path);
    if (!out.is_open()) {
        return false;
    }
    out << "scenario=" << request.label << '\n';
    out << "user_label=" << request.user_label << '\n';
    out << "query_keywords=";
    for (size_t i = 0; i < request.query_keywords.size(); ++i) {
        if (i != 0) {
            out << ',';
        }
        out << request.query_keywords[i];
    }
    out << "\nfound_files=" << hits.size() << "\n\n";

    for (const auto& hit : hits) {
        out << "bundle_label=" << hit.bundle_label << '\n';
        out << "matched_keywords=";
        for (size_t i = 0; i < hit.matched_keywords.size(); ++i) {
            if (i != 0) {
                out << ',';
            }
            out << hit.matched_keywords[i];
        }
        out << "\nplaintext:\n" << hit.plaintext << "\n\n";
    }
    return true;
}

vector<QueryRequest> BuildQueryRequests() {
    // Format: {"Scenario name", "Key", {"Keywords"}}
    return {
        {"PeakS", "Peak", {}},
        {"CheeseS", "Cheese", {}},
        {"IngS", "Ing", {}},
        {"MinorS", "Minor", {}},
    };
}

bool LoadUserKeyOrFail(const SystemParams& params, const string& label, UserSecretKey& user_sk) {
    return LoadUserSecretKey(params, user_sk, kBinaryDir + "/" + label + "_userkey.bin");
}

bool LoadBundleOrFail(const SystemParams& params, const string& label, CiphertextBundle& bundle) {
    return LoadCiphertextBundle(params, bundle, kBinaryDir + "/" + label + "_ciphertext_bundle.bin");
}

vector<string> DiscoverBundleLabels() {
    vector<string> labels;
    for (const auto& entry : filesystem::directory_iterator(kBinaryDir)) {
        if (!entry.is_regular_file()) {
            continue;
        }
        const string filename = entry.path().filename().string();
        if (filename.size() > kBundleSuffix.size() &&
            filename.substr(filename.size() - kBundleSuffix.size()) == kBundleSuffix) {
            labels.push_back(filename.substr(0, filename.size() - kBundleSuffix.size()));
        }
    }
    sort(labels.begin(), labels.end());
    return labels;
}

}  // namespace

int main() {
    SystemParams params{};
    PK pk;
    MSK msk;

    if (!LoadPhase1Artifacts(params, pk, msk, kBinaryDir)) {
        cerr << "Failed to load Phase 1 artifacts from build/" << kBinaryDir
             << ". Run ./phase1_setup first." << '\n';
        return 1;
    }

    filesystem::create_directories(kReadableDir);
    filesystem::create_directories(kBinaryDir);

    const auto bundle_labels = DiscoverBundleLabels();
    if (bundle_labels.empty()) {
        cerr << "No ciphertext bundles found in build/" << kBinaryDir << ". Run ./phase3_encrypt first." << '\n';
        return 2;
    }

    const auto requests = BuildQueryRequests();
    for (const auto& request : requests) {
        UserSecretKey user_sk;
        if (!LoadUserKeyOrFail(params, request.user_label, user_sk)) {
            cerr << "Failed to load user key for " << request.user_label << '\n';
            return 3;
        }

        vector<QueryHit> hits;
        for (const auto& bundle_label : bundle_labels) {
            CiphertextBundle bundle;
            if (!LoadBundleOrFail(params, bundle_label, bundle)) {
                cerr << "Failed to load bundle for " << bundle_label << '\n';
                return 4;
            }

            SearchTrapdoor trapdoor;
            TrapGen(params, user_sk, bundle.file_nonce, request.label + "__" + bundle_label, request.query_keywords, trapdoor);
            if (!SaveSearchTrapdoor(params, trapdoor, kBinaryDir + "/" + request.label + "__" + bundle_label + "_trapdoor.bin") ||
                !WriteReadableTrapdoor(trapdoor, kReadableDir + "/" + request.label + "__" + bundle_label + "_trapdoor_readable.txt")) {
                cerr << "Failed to save trapdoor artifacts for " << request.label << " against " << bundle_label << '\n';
                return 5;
            }

            SearchResult result;
            if (RetrieveAndDecrypt(params, user_sk, bundle, trapdoor, result) && result.plaintext_recovered) {
                hits.push_back(QueryHit{bundle_label, result.matched_keywords, result.plaintext});
            }
        }

        if (!WriteQuerySummary(request, hits, kReadableDir + "/" + request.label + "_query_result.txt")) {
            cerr << "Failed to save query summary for " << request.label << '\n';
            return 6;
        }

        cout << request.label << ": " << hits.size() << " matching decryptable file(s)" << '\n';
        for (const auto& hit : hits) {
            cout << "  - " << hit.bundle_label << '\n';
        }
    }

    return 0;
}

