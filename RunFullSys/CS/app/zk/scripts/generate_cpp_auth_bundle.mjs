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
const wasmFile = path.join(repoRoot, "zk", "build", "circuit", "pqabse_membership_js", "pqabse_membership.wasm");
const zkeyFile = path.join(repoRoot, "zk", "build", "setup", "pqabse_membership_final.zkey");
const vkeyFile = path.join(repoRoot, "zk", "build", "setup", "verification_key.json");

function ensureArtifacts() {
    if (fs.existsSync(wasmFile) && fs.existsSync(zkeyFile) && fs.existsSync(vkeyFile)) {
        return;
    }

    execFileSync(process.execPath, [buildScript], {
        cwd: repoRoot,
        stdio: "inherit",
    });
}

function writeMeta(file, values) {
    const lines = Object.entries(values).map(([key, value]) => `${key}=${value}`);
    fs.writeFileSync(file, `${lines.join("\n")}\n`);
}

const args = process.argv.slice(2);
if (args.length !== 5) {
    console.error("Usage: node zk/scripts/generate_cpp_auth_bundle.mjs <state.json> <out-dir> <meta.txt> <nonce> <issuedAt>");
    process.exit(1);
}

const [stateFileRaw, outDirRaw, metaFileRaw, nonceRaw, issuedAtRaw] = args;
const [stateFile, outDir, metaFile] = [stateFileRaw, outDirRaw, metaFileRaw].map((value) => path.resolve(value));
const nonce = canonicalModQ(nonceRaw).toString();
const issuedAt = BigInt(issuedAtRaw).toString();
ensureArtifacts();
fs.mkdirSync(outDir, { recursive: true });

const state = JSON.parse(fs.readFileSync(stateFile, "utf8"));
const targetGid = state.target_gid;
const targetSecretRaw = state.target_secret;
const depth = Number(state.depth ?? 8);

const poseidon = await createPoseidonContext();
const zeroLeaf = poseidon.poseidon1(0n);
const users = (state.users ?? []).map((user) => ({
    gid: user.gid,
    leaf: user.leaf ?? poseidon.registrationLeaf(user.gid, canonicalModQ(user.secret)),
    secret: user.secret === undefined ? undefined : canonicalModQ(user.secret),
    revoked: Boolean(user.revoked),
}));

const targetIndex = users.findIndex((user) => user.gid === targetGid);
if (targetIndex < 0) {
    throw new Error(`Target user ${targetGid} is not present in state.`);
}
if (users[targetIndex].revoked) {
    throw new Error(`Target user ${targetGid} is revoked and cannot receive a proof.`);
}
const targetSecret = targetSecretRaw !== undefined
    ? canonicalModQ(targetSecretRaw)
    : users[targetIndex].secret;
if (targetSecret === undefined) {
    throw new Error(`Target user ${targetGid} is missing a private target_secret witness.`);
}

const registrationLeaves = users.map((user) => user.leaf);
const registrationTree = buildFixedDepthTree({
    depth,
    leaves: registrationLeaves,
    defaultLeaf: zeroLeaf,
    poseidon2: poseidon.poseidon2,
});

const revocationLeaves = users.map((user, index) =>
    user.revoked ? registrationLeaves[index] : zeroLeaf,
);
const revocationTree = buildFixedDepthTree({
    depth,
    leaves: revocationLeaves,
    defaultLeaf: zeroLeaf,
    poseidon2: poseidon.poseidon2,
});

const registrationProof = registrationTree.getProof(targetIndex);
const revocationProof = revocationTree.getProof(targetIndex);
const input = {
    registrationRoot: registrationTree.root,
    revocationRoot: revocationTree.root,
    pathElementsRegistration: registrationProof.pathElements,
    pathElementsRevocation: revocationProof.pathElements,
    pathIndices: registrationProof.pathIndices,
    nonce,
    issuedAt,
    gidField: gidToField(targetGid).toString(),
    identitySecret: targetSecret.toString(),
    revocationLeaf: zeroLeaf,
};

const { proof, publicSignals } = await groth16.fullProve(
    input,
    wasmFile,
    zkeyFile,
    undefined,
    { singleThread: true },
    { singleThread: true },
);

const inputFile = path.join(outDir, "input.json");
const proofFile = path.join(outDir, "proof.json");
const publicFile = path.join(outDir, "public.json");

fs.writeFileSync(inputFile, JSON.stringify(input, null, 2));
fs.writeFileSync(proofFile, JSON.stringify(proof, null, 2));
fs.writeFileSync(publicFile, JSON.stringify(publicSignals, null, 2));

writeMeta(metaFile, {
    target_gid: targetGid,
    target_index: targetIndex.toString(),
    registration_root: registrationTree.root,
    revocation_root: revocationTree.root,
    nonce,
    issued_at: issuedAt,
    proof_file: proofFile,
    public_file: publicFile,
    input_file: inputFile,
});
