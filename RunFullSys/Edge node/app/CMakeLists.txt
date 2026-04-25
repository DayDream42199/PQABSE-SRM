cmake_minimum_required(VERSION 3.10)
project(ABSE_ZKP C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(liboqs REQUIRED)
find_library(OPENFHE_CORE_LIB OPENFHEcore HINTS /usr/local/lib)
find_library(CRYPTO_LIB crypto)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/abse_include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/pq_src)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/search_include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/poseidon)
include_directories(/usr/local/include/openfhe/core)
include_directories(/usr/local/include/openfhe)

set(POSEIDON_SOURCES
    poseidon/f251.c
    poseidon/f251_int128.c
    poseidon/poseidon.c
    poseidon/poseidon_rc.c
    poseidon/platform_utils.c
)

set(ABSE_CORE_SOURCES
    abse_src/phase1_setup.cpp
    abse_src/phase2_keygen.cpp
    abse_src/phase3_encrypt.cpp
    abse_src/phase4_search.cpp
)

set(PQ_CORE_SOURCES
    pq_src/Blockchain.cpp
    pq_src/BlockchainClient.cpp
    pq_src/IdentityAuthority.cpp
    pq_src/TrustedAuthority.cpp
    pq_src/User.cpp
)

set(MERGED_SOURCES
    src/system/RuntimePaths.cpp
    src/system/Artifacts.cpp
    src/system/AuthTokenIO.cpp
    src/system/ExperimentMetrics.cpp
    src/system/NitroEnclaveProtocol.cpp
    src/system/SearchBenchmark.cpp
    src/system/TestScenario.cpp
    src/entities/NitroTeeClient.cpp
    src/entities/SoftwareTee.cpp
    src/entities/SearchGateway.cpp
    search_src/Search.cpp
    search_src/roaring.c
)

add_library(abse_zkp_core STATIC
    ${ABSE_CORE_SOURCES}
    ${PQ_CORE_SOURCES}
    ${MERGED_SOURCES}
    ${POSEIDON_SOURCES}
)

target_compile_definitions(abse_zkp_core PRIVATE ABSE_ZKP_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(abse_zkp_core PRIVATE ${OPENFHE_CORE_LIB} ${CRYPTO_LIB} OQS::oqs)

add_executable(phase1_setup apps/phase1_setup_main.cpp)
target_link_libraries(phase1_setup PRIVATE abse_zkp_core)
add_executable(phase1_verify apps/phase1_verify_main.cpp)
target_link_libraries(phase1_verify PRIVATE abse_zkp_core)
add_executable(phase2_keygen apps/phase2_keygen_main.cpp)
target_link_libraries(phase2_keygen PRIVATE abse_zkp_core)
add_executable(phase3_encrypt apps/phase3_encrypt_main.cpp)
target_link_libraries(phase3_encrypt PRIVATE abse_zkp_core)
add_executable(phase4_search apps/phase4_search_main.cpp)
target_link_libraries(phase4_search PRIVATE abse_zkp_core)
add_executable(phase5_revoke apps/phase5_revoke_main.cpp)
target_link_libraries(phase5_revoke PRIVATE abse_zkp_core)
add_executable(search_benchmark apps/search_benchmark_main.cpp)
target_link_libraries(search_benchmark PRIVATE abse_zkp_core)
add_executable(search_benchmark_sweep apps/search_benchmark_sweep_main.cpp)
target_link_libraries(search_benchmark_sweep PRIVATE abse_zkp_core)
add_executable(generate_synthetic_scenario apps/generate_synthetic_scenario_main.cpp)
target_link_libraries(generate_synthetic_scenario PRIVATE abse_zkp_core)
add_executable(materialize_scenario apps/materialize_scenario_main.cpp)
target_link_libraries(materialize_scenario PRIVATE abse_zkp_core)
add_executable(encryption_benchmark_sweep apps/encryption_benchmark_sweep_main.cpp)
target_link_libraries(encryption_benchmark_sweep PRIVATE abse_zkp_core)
add_executable(revocation_benchmark_sweep apps/revocation_benchmark_sweep_main.cpp)
target_link_libraries(revocation_benchmark_sweep PRIVATE abse_zkp_core)
add_executable(benchmark_orchestrator apps/benchmark_orchestrator_main.cpp)
target_link_libraries(benchmark_orchestrator PRIVATE abse_zkp_core)
add_executable(core_crypto_benchmark apps/core_crypto_benchmark_main.cpp)
target_link_libraries(core_crypto_benchmark PRIVATE abse_zkp_core)
add_executable(mdu_prepare_query apps/mdu_prepare_query_main.cpp)
target_link_libraries(mdu_prepare_query PRIVATE abse_zkp_core)
add_executable(cs_process_query apps/cs_process_query_main.cpp)
target_link_libraries(cs_process_query PRIVATE abse_zkp_core)
add_executable(mdu_decrypt_response apps/mdu_decrypt_response_main.cpp)
target_link_libraries(mdu_decrypt_response PRIVATE abse_zkp_core)
add_executable(nitro_encrypt_enclave_server apps/nitro_encrypt_enclave_main.cpp)
target_link_libraries(nitro_encrypt_enclave_server PRIVATE abse_zkp_core)


