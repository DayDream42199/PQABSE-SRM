import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { Scalar, utils } from "ffjavascript";
import { getCurveFromName } from "../../node_modules/snarkjs/src/curves.js";

const { unstringifyBigInts } = utils;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "..", "..");

const args = process.argv.slice(2);
if (args.length !== 2 && args.length !== 6) {
    console.error("Usage: node zk/scripts/verify_membership.mjs <public.json> <proof.json> [expectedRegistrationRoot expectedRevocationRoot expectedNonce expectedIssuedAt]");
    process.exit(1);
}

const [publicFileRaw, proofFileRaw, expectedRegistrationRoot, expectedRevocationRoot, expectedNonce, expectedIssuedAt] = args;
const publicFile = path.resolve(publicFileRaw);
const proofFile = path.resolve(proofFileRaw);
const vkeyFile = path.join(repoRoot, "zk", "build", "setup", "verification_key.json");

for (const requiredFile of [publicFile, proofFile, vkeyFile]) {
    if (!fs.existsSync(requiredFile)) {
        console.error(`Missing required file: ${requiredFile}`);
        process.exit(1);
    }
}

const vKey = JSON.parse(fs.readFileSync(vkeyFile, "utf8"));
const publicSignals = JSON.parse(fs.readFileSync(publicFile, "utf8"));
const proof = JSON.parse(fs.readFileSync(proofFile, "utf8"));

function publicInputsAreValid(curve, inputs) {
    return inputs.every((value) => Scalar.geq(value, 0) && Scalar.lt(value, curve.r));
}

const normalizedVKey = unstringifyBigInts(vKey);
const normalizedPublicSignals = unstringifyBigInts(publicSignals);
const normalizedProof = unstringifyBigInts(proof);
const curve = await getCurveFromName(normalizedVKey.curve, { singleThread: true });

if (args.length === 6) {
    if (publicSignals.length !== 4 ||
        publicSignals[0] !== expectedRegistrationRoot ||
        publicSignals[1] !== expectedRevocationRoot ||
        publicSignals[2] !== expectedNonce ||
        publicSignals[3] !== expectedIssuedAt) {
        process.stdout.write("Invalid proof\n");
        process.exit(0);
    }
}

if (!publicInputsAreValid(curve, normalizedPublicSignals)) {
    process.stdout.write("Invalid proof\n");
    process.exit(0);
}

const ic0 = curve.G1.fromObject(normalizedVKey.IC[0]);
const icBuffer = new Uint8Array(curve.G1.F.n8 * 2 * normalizedPublicSignals.length);
const scalarBuffer = new Uint8Array(curve.Fr.n8 * normalizedPublicSignals.length);

for (let i = 0; i < normalizedPublicSignals.length; i += 1) {
    const point = curve.G1.fromObject(normalizedVKey.IC[i + 1]);
    icBuffer.set(point, i * curve.G1.F.n8 * 2);
    Scalar.toRprLE(scalarBuffer, curve.Fr.n8 * i, normalizedPublicSignals[i], curve.Fr.n8);
}

let cpub = await curve.G1.multiExpAffine(icBuffer, scalarBuffer);
cpub = curve.G1.add(cpub, ic0);

const ok = await curve.pairingEq(
    curve.G1.neg(curve.G1.fromObject(normalizedProof.pi_a)),
    curve.G2.fromObject(normalizedProof.pi_b),
    cpub,
    curve.G2.fromObject(normalizedVKey.vk_gamma_2),
    curve.G1.fromObject(normalizedProof.pi_c),
    curve.G2.fromObject(normalizedVKey.vk_delta_2),
    curve.G1.fromObject(normalizedVKey.vk_alpha_1),
    curve.G2.fromObject(normalizedVKey.vk_beta_2),
);

process.stdout.write(`${ok ? "OK!" : "Invalid proof"}\n`);
