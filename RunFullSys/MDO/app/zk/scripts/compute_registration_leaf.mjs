import { canonicalModQ, createPoseidonContext } from "../lib/merkle.mjs";

const args = process.argv.slice(2);
if (args.length !== 2) {
    console.error("Usage: node zk/scripts/compute_registration_leaf.mjs <gid> <identitySecret>");
    process.exit(1);
}

const [gid, identitySecretRaw] = args;
const poseidon = await createPoseidonContext();
const leaf = poseidon.registrationLeaf(gid, canonicalModQ(identitySecretRaw));
process.stdout.write(`${leaf}\n`);
