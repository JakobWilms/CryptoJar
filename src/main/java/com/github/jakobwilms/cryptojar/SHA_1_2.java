package com.github.jakobwilms.cryptojar;

import org.jetbrains.annotations.NotNull;

import java.util.BitSet;

public abstract class SHA_1_2 extends HashAlgorithm {

    /**
     * Preprocess a BitSet with a given size. <br>
     * This algorithm executes the following steps as specified by the Federal Information Processing Standards Publication: <br>
     * 1) Padding the Message <br>
     * 2) Parsing the Message <br>
     *
     * @param bitSet The set of bits to preprocess
     * @param size   The size of the BitSet
     *
     * @return The preprocessed BitSet, as an array of BitSets, each with a size of 512
     */
    BitSet @NotNull [] preprocess(final @NotNull BitSet bitSet, int size) {
        // PADDING
        bitSet.set(size, true);
        int bitsToAdd = 0;
        for (int i = 0; i < 512; i++)
            if ((size + i + 1) % 512 == 0) {
                bitsToAdd = i;
                break;
            }
        final BitSet sizeSet = BitSet.valueOf(new long[]{size});
        for (int i = 0; i < 64; i++) bitSet.set(size + bitsToAdd + 1, sizeSet.get(i));

        // PARSING
        final BitSet[] sets = new BitSet[(size + 1 + bitsToAdd + 64) / 512];
        for (int i = 0; i < (size + 1 + bitsToAdd + 64) / 512; i++) {
            sets[i] = bitSet.get(i * 512, (i + 1) * 512);
        }

        return sets;
    }

    @Override
    public String hash(byte @NotNull [] bytes) {
        BitSet[] bitSets = preprocess(BitSet.valueOf(bytes), bytes.length * 8);
        return compute(bitSets);
    }

    abstract String compute(final @NotNull BitSet @NotNull [] sets);
}
