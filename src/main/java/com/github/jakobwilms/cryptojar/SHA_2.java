package com.github.jakobwilms.cryptojar;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;
import java.util.BitSet;

import static com.github.jakobwilms.cryptojar.SHA_Helper.*;
import static com.github.jakobwilms.cryptojar.SHA_Helper.add;

public abstract class SHA_2 extends SHA_1_2 {

    @Override
    String compute(final @NotNull BitSet @NotNull [] sets) {
        byte[][][] H0 = initialHash(sets.length + 1);

        for (int i = 0; i < sets.length; i++) {
            final byte[][] w = new byte[64][4];
            for (int t = 0; t < 64; t++)
                w[t] = t < 16 ? toWBits(sets[i].get(t * 32, (t + 1) * 32).toByteArray(), 32) :
                        add(add(add(smallSigma256_1(w[t - 2]), w[t - 7]), smallSigma256_0(w[t - 15])), w[t - 16]);
            byte[] a = H0[i][0], b = H0[i][1],
                    c = H0[i][2], d = H0[i][3],
                    e = H0[i][4], f = H0[i][5],
                    g = H0[i][6], h = H0[i][7];

            for (int t = 0; t < 64; t++) {
                byte[] t1 = add(add(add(add(h, capitalSigma256_1(e)), ch(e, f, g)), ByteBuffer.allocate(4).putInt(K256[t]).array()), w[t]);
                byte[] t2 = add(capitalSigma256_0(a), maj(a, b, c));
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

        return finalValue(H0, sets.length);
    }

    abstract byte @NotNull [][][] initialHash(final int length);

    abstract @NotNull String finalValue(final byte @NotNull [][][] H0, final int length);
}
