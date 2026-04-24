import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { groth16 } from "snarkjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "..", "..");

const args = process.argv.slice(2);
if (args.length !== 3) {
    console.error("Usage: node zk/scripts/prove_membership.mjs <input.json> <proof.json> <public.json>");
    process.exit(1);
}

const [inputFile, proofFile, publicFile] = args.map((value) => path.resolve(value));
const wasmFile = path.join(repoRoot, "zk", "build", "circuit", "pqabse_membership_js", "pqabse_membership.wasm");
const zkeyFile = path.join(repoRoot, "zk", "build", "setup", "pqabse_membership_final.zkey");

for (const requiredFile of [inputFile, wasmFile, zkeyFile]) {
    if (!fs.existsSync(requiredFile)) {
        console.error(`Missing required file: ${requiredFile}`);
        process.exit(1);
    }
}

const input = JSON.parse(fs.readFileSync(inputFile, "utf8"));
const { proof, publicSignals } = await groth16.fullProve(
    input,
    wasmFile,
    zkeyFile,
    undefined,
    { singleThread: true },
    { singleThread: true },
);

fs.writeFileSync(proofFile, JSON.stringify(proof, null, 2));
fs.writeFileSync(publicFile, JSON.stringify(publicSignals, null, 2));
