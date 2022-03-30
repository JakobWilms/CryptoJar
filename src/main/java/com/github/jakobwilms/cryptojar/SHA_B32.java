package com.github.jakobwilms.cryptojar;

import org.jetbrains.annotations.NotNull;

import java.util.BitSet;

public abstract class SHA_B32 extends HashAlgorithm {

    @Override
    public SHA2_Return hash(byte @NotNull [] bytes, final int truncate) {
        BitSet[] bitSets = preprocess(BitSet.valueOf(bytes), bytes.length * 8);
        return compute(bitSets);
    }

    protected BitSet @NotNull [] preprocess(final @NotNull BitSet bitSet, int size) {
        // PADDING
        bitSet.set(size, true);
        int bitsToAdd = 0;
        for (int i = 0; i < 512; i++)
            if ((size + i + 1) % 512 == 0) {
                bitsToAdd = i - 64;
                break;
            }
        final BitSet sizeSet = BitSet.valueOf(new long[]{size});
        final int lastSetBit = sizeSet.length();
        for (int i = 0; i < 64; i++) bitSet.set(size + bitsToAdd + 65 - lastSetBit + i, sizeSet.get(i));

        // PARSING
        final BitSet[] sets = new BitSet[(size + 1 + bitsToAdd + 64) / 512];
        for (int i = 0; i < (size + 1 + bitsToAdd + 64) / 512; i++) {
            sets[i] = bitSet.get(i * 512, (i + 1) * 512);
        }

        return sets;
    }

    abstract SHA2_Return compute(final @NotNull BitSet @NotNull [] sets);
}
