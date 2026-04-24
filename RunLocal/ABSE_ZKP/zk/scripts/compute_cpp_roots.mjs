import fs from "fs";
import path from "path";
import { execFileSync } from "child_process";
import { fileURLToPath } from "url";
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
if (args.length !== 2) {
    console.error("Usage: node zk/scripts/compute_cpp_roots.mjs <state.json> <meta.txt>");
    process.exit(1);
}

const [stateFile, metaFile] = args.map((value) => path.resolve(value));
ensureArtifacts();

const state = JSON.parse(fs.readFileSync(stateFile, "utf8"));
const poseidon = await createPoseidonContext();
const zeroLeaf = poseidon.poseidon1(0n);
const depth = Number(state.depth ?? 8);
const users = (state.users ?? []).map((user) => ({
    gid: user.gid,
    leaf: user.leaf ?? poseidon.registrationLeaf(user.gid, canonicalModQ(user.secret)),
    revoked: Boolean(user.revoked),
}));

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

writeMeta(metaFile, {
    registration_root: registrationTree.root,
    revocation_root: revocationTree.root,
    user_count: users.length.toString(),
});
