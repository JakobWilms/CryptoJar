package com.github.jakobwilms.cryptojar;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;
import java.util.BitSet;

public abstract class SHA_2_B32 extends SHA_B32 {

    ///////////////
    // CONSTANTS //
    ///////////////

    private final int @NotNull [] K256 = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    private final int @NotNull [] _H256 = {
            0x6a09e667, 0xbb67ae85,
            0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c,
            0x1f83d9ab, 0x5be0cd19
    };

    protected final byte @NotNull [][] H256 = {
            ByteBuffer.allocate(4).putInt(_H256[0]).array(),
            ByteBuffer.allocate(4).putInt(_H256[1]).array(),
            ByteBuffer.allocate(4).putInt(_H256[2]).array(),
            ByteBuffer.allocate(4).putInt(_H256[3]).array(),
            ByteBuffer.allocate(4).putInt(_H256[4]).array(),
            ByteBuffer.allocate(4).putInt(_H256[5]).array(),
            ByteBuffer.allocate(4).putInt(_H256[6]).array(),
            ByteBuffer.allocate(4).putInt(_H256[7]).array()
    };

    @Override
    SHA2_Return compute(final @NotNull BitSet @NotNull [] sets) {
        byte[][][] H0 = initialHash(sets.length + 1);

        for (int i = 0; i < sets.length; i++) {
            final byte[][] w = new byte[64][4];
            BitwiseOperator op1 = new BitwiseOperator(0, true), op2 = new BitwiseOperator(0, true), op3 = new BitwiseOperator(0, true);
            for (int t = 0; t < 64; t++)
                w[t] = t < 16 ? trimTo(sets[i].get(t * 32, (t + 1) * 32).toByteArray(), 4) :
                        op1.set(w[t - 2]).smallSigma256_1().add(op2.set(w[t - 15]).smallSigma256_0()).add(w[t - 16]).getBytes();
            byte[] a = H0[i][0], b = H0[i][1],
                    c = H0[i][2], d = H0[i][3],
                    e = H0[i][4], f = H0[i][5],
                    g = H0[i][6], h = H0[i][7];

            for (int t = 0; t < 64; t++) {
                byte[] t1 = op1.set(h).add(op2.set(e).capitalSigma256_1())
                        .add(op3.set(e).ch(f, g))
                        .add(ByteBuffer.allocate(4).putInt(K256[t]).array())
                        .add(w[t]).getBytes();
                byte[] t2 = op1.set(a).capitalSigma256_0()
                        .add(op2.set(a).maj(b, c)).getBytes();
                h = g;
                g = f;
                f = e;
                e = op1.set(d).add(t1).getBytes();
                d = c;
                c = b;
                b = a;
                a = op1.set(t1).add(t2).getBytes();
            }

            H0[i + 1][0] = op1.set(a).add(H0[i][0]).getBytes();
            H0[i + 1][1] = op1.set(b).add(H0[i][1]).getBytes();
            H0[i + 1][2] = op1.set(c).add(H0[i][2]).getBytes();
            H0[i + 1][3] = op1.set(d).add(H0[i][3]).getBytes();
            H0[i + 1][4] = op1.set(e).add(H0[i][4]).getBytes();
            H0[i + 1][5] = op1.set(f).add(H0[i][5]).getBytes();
            H0[i + 1][6] = op1.set(g).add(H0[i][6]).getBytes();
            H0[i + 1][7] = op1.set(h).add(H0[i][7]).getBytes();
        }

        return finalValue(H0, sets.length);
    }

    abstract byte @NotNull [][][] initialHash(final int length);

    abstract @NotNull SHA2_Return finalValue(final byte @NotNull [][][] H0, final int length);
}
