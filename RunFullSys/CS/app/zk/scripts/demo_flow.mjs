import fs from "fs";
import path from "path";
import { execFileSync } from "child_process";
import { fileURLToPath } from "url";
import { groth16 } from "snarkjs";
import {
    canonicalModQ,
    createPoseidonContext,
    buildFixedDepthTree,
    gidToField,
} from "../lib/merkle.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "..", "..");

const buildScript = path.join(repoRoot, "zk", "scripts", "build_zk_assets.mjs");
const demoDir = path.join(repoRoot, "zk", "build", "demo");
const wasmFile = path.join(repoRoot, "zk", "build", "circuit", "pqabse_membership_js", "pqabse_membership.wasm");
const vkeyFile = path.join(repoRoot, "zk", "build", "setup", "verification_key.json");
const zkeyFile = path.join(repoRoot, "zk", "build", "setup", "pqabse_membership_final.zkey");

function ensureDir(dir) {
    fs.mkdirSync(dir, { recursive: true });
}

function runNode(script, args, options = {}) {
    return execFileSync(process.execPath, [script, ...args], {
        cwd: repoRoot,
        encoding: options.encoding ?? "utf8",
        stdio: options.stdio ?? "pipe",
    });
}

function ensureArtifacts() {
    if (fs.existsSync(wasmFile) && fs.existsSync(zkeyFile) && fs.existsSync(vkeyFile)) {
        return;
    }

    console.log("Preparing circuit artifacts...");
    runNode(buildScript, [], { stdio: "inherit", encoding: "utf8" });
}

function writeJson(file, value) {
    fs.writeFileSync(file, JSON.stringify(value, null, 2));
}

function treeLeavesFromUsers(users, zeroLeaf, poseidon1) {
    return users.map((user) => poseidon1(user.gid, user.secret));
}

async function main() {
    ensureDir(demoDir);
    ensureArtifacts();

    const poseidon = await createPoseidonContext();
    const zeroLeaf = poseidon.poseidon1(0n);
    const depth = 8;

    const users = [
        { gid: "Alice_GID", secret: canonicalModQ(1001) },
        { gid: "Bob_GID", secret: canonicalModQ(1002) },
        { gid: "Carol_GID", secret: canonicalModQ(12288) },
    ];

    const registrationLeaves = treeLeavesFromUsers(users, zeroLeaf, poseidon.registrationLeaf);
    const registrationTree = buildFixedDepthTree({
        depth,
        leaves: registrationLeaves,
        defaultLeaf: zeroLeaf,
        poseidon2: poseidon.poseidon2,
    });

    const revocationLeaves = Array(users.length).fill(zeroLeaf);
    const revocationTree = buildFixedDepthTree({
        depth,
        leaves: revocationLeaves,
        defaultLeaf: zeroLeaf,
        poseidon2: poseidon.poseidon2,
    });

    const bobIndex = 1;
    const bobRegistrationProof = registrationTree.getProof(bobIndex);
    const bobRevocationProof = revocationTree.getProof(bobIndex);

    const bobInput = {
        registrationRoot: registrationTree.root,
        revocationRoot: revocationTree.root,
        nonce: "77",
        issuedAt: "1700000000",
        pathElementsRegistration: bobRegistrationProof.pathElements,
        pathElementsRevocation: bobRevocationProof.pathElements,
        pathIndices: bobRegistrationProof.pathIndices,
        gidField: gidToField(users[bobIndex].gid).toString(),
        identitySecret: users[bobIndex].secret.toString(),
        revocationLeaf: zeroLeaf,
    };

    const bobProofFile = path.join(demoDir, "bob_proof.json");
    const bobPublicFile = path.join(demoDir, "bob_public.json");
    const bobInputFile = path.join(demoDir, "bob_input.json");
    writeJson(bobInputFile, bobInput);

    console.log("\nGenerating a real proof for Bob...");
    const { proof: bobProof, publicSignals: bobPublicSignals } = await groth16.fullProve(
        bobInput,
        wasmFile,
        zkeyFile,
        undefined,
        { singleThread: true },
        { singleThread: true },
    );
    writeJson(bobProofFile, bobProof);
    writeJson(bobPublicFile, bobPublicSignals);

    console.log("\nVerifying Bob's proof against the published roots...");
    const verificationKey = JSON.parse(fs.readFileSync(vkeyFile, "utf8"));
    const bobVerify = await groth16.verify(verificationKey, bobPublicSignals, bobProof);
    console.log(bobVerify ? "OK!" : "Invalid proof");

    const tamperedPublicFile = path.join(demoDir, "bob_public_tampered.json");
    const tamperedPublic = [...bobPublicSignals];
    tamperedPublic[3] = poseidon.poseidon2(tamperedPublic[3], "1");
    writeJson(tamperedPublicFile, tamperedPublic);

    console.log("\nVerifying the same proof against a tampered revocation root...");
    const tamperedVerify = await groth16.verify(verificationKey, tamperedPublic, bobProof);
    console.log(tamperedVerify ? "OK!" : "Invalid proof");

    console.log("\nRevoking Alice and checking that her proof can no longer be generated honestly...");
    revocationLeaves[0] = registrationLeaves[0];
    const revokedTree = buildFixedDepthTree({
        depth,
        leaves: revocationLeaves,
        defaultLeaf: zeroLeaf,
        poseidon2: poseidon.poseidon2,
    });

    const aliceIndex = 0;
    const aliceRegistrationProof = registrationTree.getProof(aliceIndex);
    const aliceRevocationProof = revokedTree.getProof(aliceIndex);
    const aliceInput = {
        registrationRoot: registrationTree.root,
        revocationRoot: revokedTree.root,
        nonce: "88",
        issuedAt: "1700000060",
        pathElementsRegistration: aliceRegistrationProof.pathElements,
        pathElementsRevocation: aliceRevocationProof.pathElements,
        pathIndices: aliceRegistrationProof.pathIndices,
        gidField: gidToField(users[aliceIndex].gid).toString(),
        identitySecret: users[aliceIndex].secret.toString(),
        revocationLeaf: zeroLeaf,
    };

    const aliceProofFile = path.join(demoDir, "alice_proof_after_revocation.json");
    const alicePublicFile = path.join(demoDir, "alice_public_after_revocation.json");
    const aliceInputFile = path.join(demoDir, "alice_input_after_revocation.json");
    writeJson(aliceInputFile, aliceInput);

    try {
        const { proof: aliceProof, publicSignals: alicePublicSignals } = await groth16.fullProve(
            aliceInput,
            wasmFile,
            zkeyFile,
            undefined,
            { singleThread: true },
            { singleThread: true },
        );
        writeJson(aliceProofFile, aliceProof);
        writeJson(alicePublicFile, alicePublicSignals);
        console.log("Unexpected result: Alice still generated a non-revocation proof.");
        process.exitCode = 1;
    } catch (error) {
        console.log("Alice proof generation failed as expected after revocation.");
    }

    console.log("\nDemo artifacts written to:");
    console.log(demoDir);
}

main().catch((error) => {
    console.error(error);
    process.exit(1);
});
