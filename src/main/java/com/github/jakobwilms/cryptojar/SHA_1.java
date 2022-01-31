package com.github.jakobwilms.cryptojar;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;
import java.util.BitSet;

import static com.github.jakobwilms.cryptojar.SHA_Helper.*;

public class SHA_1 extends SHA_1_2 {

    private static final SHA_1 INSTANCE = new SHA_1();

    private SHA_1() {}

    public static SHA_1 getInstance() {
        return INSTANCE;
    }

    @Override
    String compute(@NotNull BitSet @NotNull [] sets) {
        byte[][][] H0 = new byte[sets.length + 1][5][];
        H0[0] = new byte[][]{
                toWBits(ByteBuffer.allocate(4).putInt(H1[0]).array(), 32),
                toWBits(ByteBuffer.allocate(4).putInt(H1[1]).array(), 32),
                toWBits(ByteBuffer.allocate(4).putInt(H1[2]).array(), 32),
                toWBits(ByteBuffer.allocate(4).putInt(H1[3]).array(), 32),
                toWBits(ByteBuffer.allocate(4).putInt(H1[4]).array(), 32)
        };

        for (int i = 0; i < sets.length; i++) {
            final byte[][] w = new byte[80][4];
            for (int t = 0; t < 80; t++)
                w[t] = t < 16 ? toWBits(sets[i].get(t * 32, (t + 1) * 32).toByteArray(), 32) :
                        rotateLeft(1, xor(xor(xor(w[t - 3], w[t - 8]), w[t - 14]), w[t - 16]));
            byte[] a = H0[i][0], b = H0[i][1], c = H0[i][2], d = H0[i][3], e = H0[i][4];

            for (int t = 0; t < 80; t++) {
                byte[] t1 = add(add(add(add(rotateLeft(5, a), f(t, b, c, d)), e), ByteBuffer.allocate(4).putInt(K1[t]).array()), w[t]);
                e = d;
                d = c;
                c = rotateLeft(30, b);
                b = a;
                a = t1;
            }

            H0[i + 1][0] = add(a, H0[i][0]);
            H0[i + 1][1] = add(a, H0[i][1]);
            H0[i + 1][2] = add(a, H0[i][2]);
            H0[i + 1][3] = add(a, H0[i][3]);
            H0[i + 1][4] = add(a, H0[i][4]);
        }

        BitSet set = new BitSet(256);
        for (int i = 0; i < 5; i++) {
            BitSet subSet = BitSet.valueOf(H0[sets.length][i]);
            for (int j = 0; j < 32; j++) {
                set.set(i * 32 + j, subSet.get(j));
            }
        }
        final byte[] hashedBytes = set.toByteArray();
        StringBuilder hashedHex = new StringBuilder(2 * hashedBytes.length);
        for (byte hashedByte : hashedBytes) {
            String hex = Integer.toHexString(0xff & hashedByte);
            if (hex.length() == 1) hashedHex.append('0');
            hashedHex.append(hex);
        }

        return hashedHex.toString();
    }

}
