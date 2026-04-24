pragma circom 2.2.0;

include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/poseidon.circom";

template MerkleRootFromPath(depth) {
    signal input leaf;
    signal input pathElements[depth];
    signal input pathIndices[depth];
    signal output root;

    signal levelHashes[depth + 1];
    component levelHashers[depth];

    levelHashes[0] <== leaf;

    for (var i = 0; i < depth; i++) {
        pathIndices[i] * (pathIndices[i] - 1) === 0;

        levelHashers[i] = Poseidon(2);
        levelHashers[i].inputs[0] <== levelHashes[i] + pathIndices[i] * (pathElements[i] - levelHashes[i]);
        levelHashers[i].inputs[1] <== pathElements[i] + pathIndices[i] * (levelHashes[i] - pathElements[i]);
        levelHashes[i + 1] <== levelHashers[i].out;
    }

    root <== levelHashes[depth];
}

template PQABSEMembership(depth) {
    signal input registrationRoot;
    signal input revocationRoot;
    signal input nonce;
    signal input issuedAt;

    signal input pathElementsRegistration[depth];
    signal input pathElementsRevocation[depth];
    signal input pathIndices[depth];

    signal input gidField;
    signal input identitySecret;
    signal input revocationLeaf;

    signal registrationLeaf;
    signal defaultRevocationLeaf;

    component gidRangeCheck = LessThan(14);
    gidRangeCheck.in[0] <== gidField;
    gidRangeCheck.in[1] <== 12289;
    gidRangeCheck.out === 1;

    component secretRangeCheck = LessThan(14);
    secretRangeCheck.in[0] <== identitySecret;
    secretRangeCheck.in[1] <== 12289;
    secretRangeCheck.out === 1;

    component nonceRangeCheck = LessThan(14);
    nonceRangeCheck.in[0] <== nonce;
    nonceRangeCheck.in[1] <== 12289;
    nonceRangeCheck.out === 1;

    component registrationHasher = Poseidon(2);
    registrationHasher.inputs[0] <== gidField;
    registrationHasher.inputs[1] <== identitySecret;
    registrationLeaf <== registrationHasher.out;

    component registrationPath = MerkleRootFromPath(depth);
    registrationPath.leaf <== registrationLeaf;
    for (var i = 0; i < depth; i++) {
        registrationPath.pathElements[i] <== pathElementsRegistration[i];
        registrationPath.pathIndices[i] <== pathIndices[i];
    }
    registrationPath.root === registrationRoot;

    component defaultRevocationHasher = Poseidon(1);
    defaultRevocationHasher.inputs[0] <== 0;
    defaultRevocationLeaf <== defaultRevocationHasher.out;
    revocationLeaf === defaultRevocationLeaf;

    component revocationPath = MerkleRootFromPath(depth);
    revocationPath.leaf <== revocationLeaf;
    for (var j = 0; j < depth; j++) {
        revocationPath.pathElements[j] <== pathElementsRevocation[j];
        revocationPath.pathIndices[j] <== pathIndices[j];
    }
    revocationPath.root === revocationRoot;
}

component main {public [registrationRoot, revocationRoot, nonce, issuedAt]} = PQABSEMembership(8);
