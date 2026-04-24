#ifndef PHASE1_SETUP_H
#define PHASE1_SETUP_H

#include <openfhe/core/lattice/hal/lat-backend.h>
#include <openfhe/core/lattice/trapdoor.h>

#include <cstdint>
#include <memory>
#include <string>

struct SystemParams {
    uint32_t ring_dim;
    uint64_t modulus;
    double trapdoor_stddev;
    int64_t gadget_base;
    bool balanced;
    size_t trapdoor_k;
};

using TrapdoorElement = lbcrypto::Poly;
using TrapdoorMatrix = lbcrypto::Matrix<TrapdoorElement>;
using TrapdoorPair = lbcrypto::RLWETrapdoorPair<TrapdoorElement>;
using ElementParams = TrapdoorElement::Params;

struct PK {
    TrapdoorMatrix A;
};

struct MSK {
    TrapdoorPair trapdoor;
};

void InitSystemParams(SystemParams& params, uint32_t ring_dim, uint64_t modulus, double trapdoor_stddev = 3.2,
                      int64_t gadget_base = 2, bool balanced = false);
std::shared_ptr<ElementParams> BuildElementParams(const SystemParams& params);
void Setup(SystemParams& params, PK& pk, MSK& msk);
TrapdoorElement MakeDeterministicSyndrome(const SystemParams& params, const std::string& label);
TrapdoorMatrix SamplePreimage(const SystemParams& params, const PK& pk, const MSK& msk,
                              const TrapdoorElement& syndrome);
bool VerifyPreimage(const PK& pk, const TrapdoorElement& syndrome, const TrapdoorMatrix& preimage);
bool SavePhase1Artifacts(const SystemParams& params, const PK& pk, const MSK& msk,
                         const std::string& directory = ".");
bool LoadPhase1Artifacts(SystemParams& params, PK& pk, MSK& msk, const std::string& directory = ".");

#endif
