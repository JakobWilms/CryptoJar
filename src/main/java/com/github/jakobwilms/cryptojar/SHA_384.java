package com.github.jakobwilms.cryptojar;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;
import java.util.BitSet;

import static com.github.jakobwilms.cryptojar.SHA_Helper.*;

public class SHA_384 extends SHA_3 {

    private static final SHA_384 INSTANCE = new SHA_384();

    public static SHA_384 getInstance() {
        return INSTANCE;
    }

    private SHA_384() {}

    @Override
    byte @NotNull [][][] initialHash(int length) {
        final byte[][][] H0 = new byte[length][8][];
        H0[0] = new byte[][]{
                toWBits(ByteBuffer.allocate(8).putLong(H384[0]).array(), 64),
                toWBits(ByteBuffer.allocate(8).putLong(H384[1]).array(), 64),
                toWBits(ByteBuffer.allocate(8).putLong(H384[2]).array(), 64),
                toWBits(ByteBuffer.allocate(8).putLong(H384[3]).array(), 64),
                toWBits(ByteBuffer.allocate(8).putLong(H384[4]).array(), 64),
                toWBits(ByteBuffer.allocate(8).putLong(H384[5]).array(), 64),
                toWBits(ByteBuffer.allocate(8).putLong(H384[6]).array(), 64),
                toWBits(ByteBuffer.allocate(8).putLong(H384[7]).array(), 64)
        };

        return H0;
    }

    @Override
    String finalValue(byte @NotNull [][][] H0, int length, final int truncate) {
        BitSet set = new BitSet(384);
        for (int i = 0; i < 6; i++) {
            BitSet subSet = BitSet.valueOf(H0[length][i]);
            for (int j = 0; j < 64; j++) {
                set.set(i * 64 + j, subSet.get(j));
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
