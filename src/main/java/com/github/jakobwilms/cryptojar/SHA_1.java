package com.github.jakobwilms.cryptojar;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.BitSet;

public class SHA_1 extends SHA_B32 {

    //////////////
    // INSTANCE //
    //////////////

    private static final SHA_1 INSTANCE = new SHA_1();

    private SHA_1() {}

    public static SHA_1 getInstance() {
        return INSTANCE;
    }

    ///////////////
    // CONSTANTS //
    ///////////////

    private final int @NotNull [] K1 = {
            0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,
            0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,
            0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,
            0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,
            0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc,
            0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc,
            0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6,
            0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6
    };

    private final int @NotNull [] _H1 = {
            0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
    };

    private final byte @NotNull [][] H1 = {
            ByteBuffer.allocate(4).putInt(_H1[0]).array(),
            ByteBuffer.allocate(4).putInt(_H1[1]).array(),
            ByteBuffer.allocate(4).putInt(_H1[2]).array(),
            ByteBuffer.allocate(4).putInt(_H1[3]).array(),
            ByteBuffer.allocate(4).putInt(_H1[4]).array()
    };

    @Override
    SHA2_Return compute(@NotNull BitSet @NotNull [] sets) {
        byte[][][] H0 = new byte[sets.length + 1][5][];
        H0[0] = Arrays.copyOf(H1, H1.length);

        for (int i = 0; i < sets.length; i++) {
            final byte[][] w = new byte[80][4];
            BitwiseOperator op1 = new BitwiseOperator(), op2 = new BitwiseOperator();
            for (int t = 0; t < 80; t++)
                w[t] = t < 16 ? trimTo(sets[i].get(t * 32, (t + 1) * 32).toByteArray(), 4) :
                        op1.set(w[t - 3]).xor(w[t - 8]).xor(w[t - 14]).xor(w[t - 16]).rotate(-1).getBytes();
            byte[] a = H0[i][0], b = H0[i][1], c = H0[i][2], d = H0[i][3], e = H0[i][4];

            for (int t = 0; t < 80; t++) {
                byte[] t1 = op1.set(a).rotate(-5)
                        .add(op2.set(b).f(t, c, d).get())
                        .add(e).add(ByteBuffer.allocate(4).putInt(K1[t]).array())
                        .add(w[t]).getBytes();
                e = d;
                d = c;
                c = op1.set(b).rotate(-30).getBytes();
                b = a;
                a = t1;
            }

            for (int t = 0; t < 5; t++)
                H0[i + 1][t] = op1.set(a).add(H0[i][0]).getBytes();
        }

        return new SHA2_Return.SHA_1_HashReturn(H0, sets.length);
    }

}
