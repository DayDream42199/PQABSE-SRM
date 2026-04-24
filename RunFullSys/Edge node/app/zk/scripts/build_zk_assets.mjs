import fs from "fs";
import path from "path";
import { execFileSync } from "child_process";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "..", "..");

const circuitFile = path.join(repoRoot, "zk", "circuits", "pqabse_membership.circom");
const buildRoot = path.join(repoRoot, "zk", "build");
const circuitOutDir = path.join(buildRoot, "circuit");
const setupDir = path.join(buildRoot, "setup");
const circomBinary = process.env.CIRCOM_BIN || "circom";
const snarkjsCli = path.join(repoRoot, "node_modules", "snarkjs", "build", "cli.cjs");

const r1csFile = path.join(circuitOutDir, "pqabse_membership.r1cs");
const wasmFile = path.join(circuitOutDir, "pqabse_membership_js", "pqabse_membership.wasm");
const zkeyFile = path.join(setupDir, "pqabse_membership_final.zkey");
const vkeyFile = path.join(setupDir, "verification_key.json");

function ensureDir(dir) {
    fs.mkdirSync(dir, { recursive: true });
}

function run(program, args, cwd = repoRoot) {
    console.log(`\n> ${program} ${args.join(" ")}`);
    execFileSync(program, args, {
        cwd,
        stdio: "inherit",
    });
}

function runSnarkjs(args) {
    run("node", [snarkjsCli, ...args]);
}

function exists(file) {
    return fs.existsSync(file);
}

ensureDir(buildRoot);
ensureDir(circuitOutDir);
ensureDir(setupDir);



run(circomBinary, [circuitFile, "--r1cs", "--wasm", "--sym", "-o", circuitOutDir]);

const tauPower = "14";
const ptau0 = path.join(setupDir, `powersOfTau28_hez_${tauPower}_0000.ptau`);
const ptau1 = path.join(setupDir, `powersOfTau28_hez_${tauPower}_0001.ptau`);
const ptauFinal = path.join(setupDir, `powersOfTau28_hez_${tauPower}_final.ptau`);
const zkey0 = path.join(setupDir, "pqabse_membership_0000.zkey");

if (!exists(ptauFinal)) {
    runSnarkjs(["powersoftau", "new", "bn128", tauPower, ptau0]);
    runSnarkjs([
        "powersoftau",
        "contribute",
        ptau0,
        ptau1,
        "--name=PQABSE first contribution",
        "--entropy=poseidon-membership-flow",
    ]);
    runSnarkjs(["powersoftau", "prepare", "phase2", ptau1, ptauFinal]);
}

runSnarkjs(["groth16", "setup", r1csFile, ptauFinal, zkey0]);
runSnarkjs([
    "zkey",
    "contribute",
    zkey0,
    zkeyFile,
    "--name=PQABSE circuit finalization",
    "--entropy=poseidon-membership-zkey",
]);
runSnarkjs(["zkey", "export", "verificationkey", zkeyFile, vkeyFile]);

if (!exists(wasmFile) || !exists(zkeyFile) || !exists(vkeyFile)) {
    throw new Error("ZK build completed without all required artifacts.");
}

console.log("\nArtifacts ready:");
console.log(`- WASM: ${wasmFile}`);
console.log(`- ZKey: ${zkeyFile}`);
console.log(`- Verification key: ${vkeyFile}`);


