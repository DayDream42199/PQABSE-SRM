import { createPoseidonContext } from "../lib/merkle.mjs";

const poseidon = await createPoseidonContext();
process.stdout.write(`${poseidon.poseidon1(0n)}\n`);
