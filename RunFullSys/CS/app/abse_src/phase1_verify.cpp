#include <iostream>
#include <string>
#include <vector>

#include "phase1_setup.h"

using namespace std;

namespace {

const string kBinaryDir = "Output/Binary";

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

    const vector<string> labels = {"phase1-check-1", "phase1-check-2", "phase1-check-3"};
    for (const auto& label : labels) {
        const TrapdoorElement syndrome = MakeDeterministicSyndrome(params, label);
        const TrapdoorMatrix preimage = SamplePreimage(params, pk, msk, syndrome);
        if (!VerifyPreimage(pk, syndrome, preimage)) {
            cerr << "Preimage verification failed for label: " << label << '\n';
            return 2;
        }
    }

    cout << "[PROOF SUCCESSFUL]: Phase 1 artifacts loaded from disk and OpenFHE Gaussian preimage sampling verified." << endl;
    return 0;
}
