import { buildPoseidon } from "circomlibjs";

export const MOD_Q = 12289n;

function toBigInt(value) {
    if (typeof value === "bigint") {
        return value;
    }
    if (typeof value === "number") {
        return BigInt(value);
    }
    if (typeof value === "string") {
        return BigInt(value);
    }
    throw new TypeError(`Unsupported field value: ${value}`);
}

export function canonicalModQ(value) {
    let normalized = toBigInt(value);
    if (normalized === 12288n) {
        normalized = -1n;
    }

    normalized %= MOD_Q;
    if (normalized < 0n) {
        normalized += MOD_Q;
    }
    return normalized;
}

export function gidToField(gid) {
    let acc = 0n;
    for (let i = 0; i < gid.length; i += 1) {
        acc = (acc * 257n + BigInt(gid.charCodeAt(i))) % MOD_Q;
    }
    return canonicalModQ(acc);
}

export async function createPoseidonContext() {
    const poseidon = await buildPoseidon();
    const field = poseidon.F;

    const toFieldString = (value) => field.toString(value);
    const poseidonHash = (inputs) => toFieldString(poseidon(inputs.map(toBigInt)));

    return {
        field,
        toFieldString,
        poseidonHash,
        poseidon1(value) {
            return poseidonHash([value]);
        },
        poseidon2(left, right) {
            return poseidonHash([left, right]);
        },
        registrationLeaf(gid, secret) {
            return poseidonHash([gidToField(gid), canonicalModQ(secret)]);
        },
    };
}

export function buildFixedDepthTree({ depth, leaves, defaultLeaf, poseidon2 }) {
    const totalLeaves = 1 << depth;
    const normalizedLeaves = Array.from({ length: totalLeaves }, (_, index) =>
        index < leaves.length ? leaves[index] : defaultLeaf,
    );

    const levels = [normalizedLeaves];
    while (levels[levels.length - 1].length > 1) {
        const current = levels[levels.length - 1];
        const next = [];

        for (let i = 0; i < current.length; i += 2) {
            next.push(poseidon2(current[i], current[i + 1]));
        }

        levels.push(next);
    }

    return {
        depth,
        levels,
        root: levels[levels.length - 1][0],
        getProof(index) {
            if (index < 0 || index >= totalLeaves) {
                throw new RangeError(`Leaf index ${index} is outside the tree capacity ${totalLeaves}`);
            }

            const pathElements = [];
            const pathIndices = [];
            let currentIndex = index;

            for (let level = 0; level < depth; level += 1) {
                const nodes = levels[level];
                const siblingIndex = currentIndex ^ 1;
                pathElements.push(nodes[siblingIndex]);
                pathIndices.push(currentIndex & 1);
                currentIndex >>= 1;
            }

            return {
                pathElements,
                pathIndices,
            };
        },
    };
}
