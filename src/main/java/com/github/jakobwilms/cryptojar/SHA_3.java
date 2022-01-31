package com.github.jakobwilms.cryptojar;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.nio.ByteBuffer;
import java.util.BitSet;

import static com.github.jakobwilms.cryptojar.SHA_Helper.*;
import static com.github.jakobwilms.cryptojar.SHA_Helper.add;

public abstract class SHA_3 extends HashAlgorithm {

    @Override
    public String hash(byte @NotNull [] bytes, final int truncate) {
        BitSet[] bitSets = preprocess(BitSet.valueOf(bytes), bytes.length * 8);
        return finalValue(compute(bitSets, truncate, null), bitSets.length, -1);
    }

    @Override
    BitSet @NotNull [] preprocess(@NotNull BitSet bitSet, int size) {
        // PADDING
        bitSet.set(size, true);
        int bitsToAdd = 0;
        for (int i = 0; i < 1024; i++)
            if ((size + i + 1) % 1024 == 0) {
                bitsToAdd = i;
                break;
            }
        final BitSet sizeSet = BitSet.valueOf(new long[]{size});
        for (int i = 0; i < 128; i++) bitSet.set(size + bitsToAdd + 1, sizeSet.get(i));

        // PARSING
        final BitSet[] sets = new BitSet[(size + 1 + bitsToAdd + 128) / 1024];
        for (int i = 0; i < (size + 1 + bitsToAdd + 128) / 1024; i++) {
            sets[i] = bitSet.get(i * 1024, (i + 1) * 1024);
        }

        return sets;
    }

    byte @NotNull [][][] compute(final @NotNull BitSet @NotNull [] sets, final int truncate, byte @Nullable [][][] h0) {
        byte[][][] H0 = h0 == null ? initialHash(sets.length + 1) : h0;

        for (int i = 0; i < sets.length; i++) {
            final byte[][] w = new byte[80][8];
            for (int t = 0; t < 80; t++)
                w[t] = t < 16 ? toWBits(sets[i].get(t * 64, (t + 1) * 64).toByteArray(), 64) :
                        add(add(add(smallSigma512_1(w[t - 2]), w[t - 7]), smallSigma512_0(w[t - 15])), w[t - 16]);
            byte[] a = H0[i][0], b = H0[i][1],
                    c = H0[i][2], d = H0[i][3],
                    e = H0[i][4], f = H0[i][5],
                    g = H0[i][6], h = H0[i][7];

            for (int t = 0; t < 80; t++) {
                byte[] t1 = add(add(add(add(h, capitalSigma512_1(e)), ch(e, f, g)), ByteBuffer.allocate(8).putLong(K512[t]).array()), w[t]);
                byte[] t2 = add(capitalSigma512_0(a), maj(a, b, c));
                h = g;
                g = f;
                f = e;
                e = add(d, t1);
                d = c;
                c = b;
                b = a;
                a = add(t1, t2);
            }

            H0[i + 1][0] = add(a, H0[i][0]);
            H0[i + 1][1] = add(a, H0[i][1]);
            H0[i + 1][2] = add(a, H0[i][2]);
            H0[i + 1][3] = add(a, H0[i][3]);
            H0[i + 1][4] = add(a, H0[i][4]);
            H0[i + 1][5] = add(a, H0[i][5]);
            H0[i + 1][6] = add(a, H0[i][6]);
            H0[i + 1][7] = add(a, H0[i][7]);
        }

        return H0;
    }

    abstract String finalValue(final byte @NotNull [][][] H0, final int length, final int truncate);

    abstract byte @NotNull [][][] initialHash(final int length);
}
