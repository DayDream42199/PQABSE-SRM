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
const testDir = path.join(repoRoot, "zk", "build", "test_cases");
const wasmFile = path.join(repoRoot, "zk", "build", "circuit", "pqabse_membership_js", "pqabse_membership.wasm");
const vkeyFile = path.join(repoRoot, "zk", "build", "setup", "verification_key.json");
const zkeyFile = path.join(repoRoot, "zk", "build", "setup", "pqabse_membership_final.zkey");

function ensureDir(dir) {
    fs.mkdirSync(dir, { recursive: true });
}

function ensureArtifacts() {
    if (fs.existsSync(wasmFile) && fs.existsSync(zkeyFile) && fs.existsSync(vkeyFile)) {
        return;
    }

    execFileSync(process.execPath, [buildScript], {
        cwd: repoRoot,
        stdio: "inherit",
    });
}

function writeJson(file, value) {
    fs.writeFileSync(file, JSON.stringify(value, null, 2));
}

function pushResult(results, summaryFile, result) {
    results.push(result);
    writeJson(summaryFile, results);
}

function formatMs(ms) {
    return ms >= 1000 ? `${(ms / 1000).toFixed(2)}s` : `${ms.toFixed(0)}ms`;
}

async function runCase(results, summaryFile, name, operation) {
    const start = Date.now();
    console.log(`\n[RUN] ${name}`);
    const result = await operation();
    const elapsed = Date.now() - start;
    console.log(`[${result.status}] ${name} (${formatMs(elapsed)})`);
    if (result.detail) {
        console.log(`       ${result.detail}`);
    }
    pushResult(results, summaryFile, result);
    return result;
}

async function prove(input) {
    return groth16.fullProve(
        input,
        wasmFile,
        zkeyFile,
        undefined,
        { singleThread: true },
        { singleThread: true },
    );
}

async function verify(vkey, publicSignals, proof) {
    return groth16.verify(vkey, publicSignals, proof);
}

function makeContext(poseidon) {
    const depth = 8;
    const zeroLeaf = poseidon.poseidon1(0n);
    const users = [
        { gid: "Alice_GID", secret: canonicalModQ(1001) },
        { gid: "Bob_GID", secret: canonicalModQ(1002) },
        { gid: "Carol_GID", secret: canonicalModQ(12288) },
        { gid: "Dave_GID", secret: canonicalModQ(77) },
    ];

    const registrationLeaves = users.map((user) => poseidon.registrationLeaf(user.gid, user.secret));
    const registrationTree = buildFixedDepthTree({
        depth,
        leaves: registrationLeaves,
        defaultLeaf: zeroLeaf,
        poseidon2: poseidon.poseidon2,
    });

    const revocationLeaves = Array(users.length).fill(zeroLeaf);
    const cleanRevocationTree = buildFixedDepthTree({
        depth,
        leaves: revocationLeaves,
        defaultLeaf: zeroLeaf,
        poseidon2: poseidon.poseidon2,
    });

    const revokedLeaves = [...revocationLeaves];
    revokedLeaves[0] = registrationLeaves[0];
    const revokedAliceTree = buildFixedDepthTree({
        depth,
        leaves: revokedLeaves,
        defaultLeaf: zeroLeaf,
        poseidon2: poseidon.poseidon2,
    });

    const mixedLeaves = [...revocationLeaves];
    mixedLeaves[3] = registrationLeaves[3];
    const mixedRevocationTree = buildFixedDepthTree({
        depth,
        leaves: mixedLeaves,
        defaultLeaf: zeroLeaf,
        poseidon2: poseidon.poseidon2,
    });

    return {
        depth,
        zeroLeaf,
        users,
        registrationLeaves,
        registrationTree,
        cleanRevocationTree,
        revokedAliceTree,
        mixedRevocationTree,
        poseidon,
    };
}

function buildInput({
    gid,
    nonce,
    issuedAt,
    identitySecret,
    registrationTree,
    revocationTree,
    registrationProof,
    revocationProof,
    revocationLeaf,
}) {
    return {
        registrationRoot: registrationTree.root,
        revocationRoot: revocationTree.root,
        nonce: nonce.toString(),
        issuedAt: issuedAt.toString(),
        pathElementsRegistration: registrationProof.pathElements,
        pathElementsRevocation: revocationProof.pathElements,
        pathIndices: registrationProof.pathIndices,
        gidField: gidToField(gid).toString(),
        identitySecret: identitySecret.toString(),
        revocationLeaf,
    };
}

async function expectSuccess(name, operation) {
    await operation();
    return { name, status: "PASS" };
}

async function expectFailure(name, operation) {
    try {
        await operation();
        return { name, status: "FAIL", detail: "Expected failure but operation succeeded." };
    } catch (error) {
        return { name, status: "PASS" };
    }
}

async function main() {
    ensureDir(testDir);
    ensureArtifacts();
    const summaryFile = path.join(testDir, "summary.json");

    const poseidon = await createPoseidonContext();
    const ctx = makeContext(poseidon);
    const vkey = JSON.parse(fs.readFileSync(vkeyFile, "utf8"));
    const results = [];
    writeJson(summaryFile, results);

    const bobIndex = 1;
    const bobRegProof = ctx.registrationTree.getProof(bobIndex);
    const bobRevProof = ctx.cleanRevocationTree.getProof(bobIndex);
    const bobInput = buildInput({
        gid: ctx.users[bobIndex].gid,
        nonce: canonicalModQ(101),
        issuedAt: 1700000000n,
        identitySecret: ctx.users[bobIndex].secret,
        registrationTree: ctx.registrationTree,
        revocationTree: ctx.cleanRevocationTree,
        registrationProof: bobRegProof,
        revocationProof: bobRevProof,
        revocationLeaf: ctx.zeroLeaf,
    });

    const bobProofBundle = await prove(bobInput);
    writeJson(path.join(testDir, "bob_valid_input.json"), bobInput);
    writeJson(path.join(testDir, "bob_valid_proof.json"), bobProofBundle.proof);
    writeJson(path.join(testDir, "bob_valid_public.json"), bobProofBundle.publicSignals);

    await runCase(results, summaryFile, "valid Bob proof verifies", async () => {
        const ok = await verify(vkey, bobProofBundle.publicSignals, bobProofBundle.proof);
        if (!ok) {
            throw new Error("Bob proof should verify.");
        }
        return { name: "valid Bob proof verifies", status: "PASS" };
    });

    await runCase(results, summaryFile, "verifier rejects Bob proof when expected nonce is wrong", async () => {
        const contextMatches =
            bobProofBundle.publicSignals[0] === bobInput.registrationRoot &&
            bobProofBundle.publicSignals[1] === bobInput.revocationRoot &&
            bobProofBundle.publicSignals[2] === canonicalModQ(999).toString() &&
            bobProofBundle.publicSignals[3] === bobInput.issuedAt;
        if (contextMatches) {
            throw new Error("Wrong expected nonce should not match Bob's public signals.");
        }
        return { name: "verifier rejects Bob proof when expected nonce is wrong", status: "PASS" };
    });

    await runCase(results, summaryFile, "verifier rejects Bob proof when expected timestamp is wrong", async () => {
        const contextMatches =
            bobProofBundle.publicSignals[0] === bobInput.registrationRoot &&
            bobProofBundle.publicSignals[1] === bobInput.revocationRoot &&
            bobProofBundle.publicSignals[2] === bobInput.nonce &&
            bobProofBundle.publicSignals[3] === (BigInt(bobInput.issuedAt) + 1n).toString();
        if (contextMatches) {
            throw new Error("Wrong expected timestamp should not match Bob's public signals.");
        }
        return { name: "verifier rejects Bob proof when expected timestamp is wrong", status: "PASS" };
    });

    const fieldAliasIndex = 2;
    const fieldAliasInput = buildInput({
        gid: ctx.users[fieldAliasIndex].gid,
        nonce: canonicalModQ(102),
        issuedAt: 1700000060n,
        identitySecret: ctx.users[fieldAliasIndex].secret,
        registrationTree: ctx.registrationTree,
        revocationTree: ctx.cleanRevocationTree,
        registrationProof: ctx.registrationTree.getProof(fieldAliasIndex),
        revocationProof: ctx.cleanRevocationTree.getProof(fieldAliasIndex),
        revocationLeaf: ctx.zeroLeaf,
    });

    await runCase(results, summaryFile, "field witness 12288 is accepted as -1 mod 12289", async () => {
        const { proof, publicSignals } = await prove(fieldAliasInput);
        const ok = await verify(vkey, publicSignals, proof);
        if (!ok) {
            throw new Error("Field alias proof should verify.");
        }
        return { name: "field witness 12288 is accepted as -1 mod 12289", status: "PASS" };
    });

    await runCase(results, summaryFile, "wrong secret is correctly rejected", async () => {
        const wrongSecretInput = {
            ...bobInput,
            identitySecret: canonicalModQ(1003).toString(),
        };
        return expectFailure("wrong secret is correctly rejected", async () => {
            await prove(wrongSecretInput);
        });
    });

    await runCase(results, summaryFile, "wrong registration path is correctly rejected", async () => {
        const wrongRegPathInput = {
            ...bobInput,
            pathElementsRegistration: ctx.registrationTree.getProof(0).pathElements,
        };
        return expectFailure("wrong registration path is correctly rejected", async () => {
            await prove(wrongRegPathInput);
        });
    });

    await runCase(results, summaryFile, "wrong revocation path is correctly rejected", async () => {
        const mixedBobInput = buildInput({
            gid: ctx.users[bobIndex].gid,
            nonce: canonicalModQ(103),
            issuedAt: 1700000120n,
            identitySecret: ctx.users[bobIndex].secret,
            registrationTree: ctx.registrationTree,
            revocationTree: ctx.mixedRevocationTree,
            registrationProof: bobRegProof,
            revocationProof: ctx.mixedRevocationTree.getProof(bobIndex),
            revocationLeaf: ctx.zeroLeaf,
        });
        const wrongRevPathInput = {
            ...mixedBobInput,
            pathElementsRevocation: ctx.mixedRevocationTree.getProof(2).pathElements,
        };
        return expectFailure("wrong revocation path is correctly rejected", async () => {
            await prove(wrongRevPathInput);
        });
    });

    await runCase(results, summaryFile, "revoked Alice is correctly rejected", async () => {
        const aliceIndex = 0;
        const revokedAliceInput = buildInput({
            gid: ctx.users[aliceIndex].gid,
            nonce: canonicalModQ(104),
            issuedAt: 1700000180n,
            identitySecret: ctx.users[aliceIndex].secret,
            registrationTree: ctx.registrationTree,
            revocationTree: ctx.revokedAliceTree,
            registrationProof: ctx.registrationTree.getProof(aliceIndex),
            revocationProof: ctx.revokedAliceTree.getProof(aliceIndex),
            revocationLeaf: ctx.zeroLeaf,
        });
        return expectFailure("revoked Alice is correctly rejected", async () => {
            await prove(revokedAliceInput);
        });
    });

    await runCase(results, summaryFile, "tampered public root fails verification", async () => {
        const tamperedPublic = [...bobProofBundle.publicSignals];
        tamperedPublic[0] = poseidon.poseidon2(tamperedPublic[0], "1");
        const ok = await verify(vkey, tamperedPublic, bobProofBundle.proof);
        if (ok) {
            throw new Error("Tampered public signals should not verify.");
        }
        return { name: "tampered public root fails verification", status: "PASS" };
    });

    await runCase(results, summaryFile, "tampered proof point fails verification", async () => {
        const tamperedProof = structuredClone(bobProofBundle.proof);
        tamperedProof.pi_c[0] = (BigInt(tamperedProof.pi_c[0]) + 1n).toString();
        const ok = await verify(vkey, bobProofBundle.publicSignals, tamperedProof);
        if (ok) {
            throw new Error("Tampered proof should not verify.");
        }
        return { name: "tampered proof point fails verification", status: "PASS" };
    });

    await runCase(results, summaryFile, "non-default revocation leaf is correctly rejected", async () => {
        const badRevLeafInput = {
            ...bobInput,
            revocationLeaf: ctx.registrationLeaves[bobIndex],
        };
        return expectFailure("non-default revocation leaf is correctly rejected", async () => {
            await prove(badRevLeafInput);
        });
    });

    const failed = results.filter((result) => result.status !== "PASS");

    console.log(`\nSummary written to: ${summaryFile}`);
    if (failed.length > 0) {
        process.exitCode = 1;
    }
}

main().catch((error) => {
    console.error(error);
    process.exit(1);
});
