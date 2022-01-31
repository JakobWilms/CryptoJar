package com.github.jakobwilms.cryptojar;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;
import java.util.BitSet;

import static com.github.jakobwilms.cryptojar.SHA_Helper.*;

public class SHA_224 extends SHA_2 {

    private static final SHA_224 INSTANCE = new SHA_224();

    public static SHA_224 getInstance() {
        return INSTANCE;
    }

    /**
     * Single Private Constructor to prevent the default one from being generated
     */
    private SHA_224() {}

    @Override
    byte @NotNull [][][] initialHash(int length) {
        byte[][][] H0 = new byte[length][8][];
        H0[0] = new byte[][]{
                toWBits(ByteBuffer.allocate(4).putInt(H224[0]).array(), 32),
                toWBits(ByteBuffer.allocate(4).putInt(H224[1]).array(), 32),
                toWBits(ByteBuffer.allocate(4).putInt(H224[2]).array(), 32),
                toWBits(ByteBuffer.allocate(4).putInt(H224[3]).array(), 32),
                toWBits(ByteBuffer.allocate(4).putInt(H224[4]).array(), 32),
                toWBits(ByteBuffer.allocate(4).putInt(H224[5]).array(), 32),
                toWBits(ByteBuffer.allocate(4).putInt(H224[6]).array(), 32),
                toWBits(ByteBuffer.allocate(4).putInt(H224[7]).array(), 32)
        };
        return H0;
    }

    @Override
    @NotNull String finalValue(byte @NotNull [][][] H0, int length) {
        BitSet set = new BitSet(256);
        for (int i = 0; i < 7; i++) {
            BitSet subSet = BitSet.valueOf(H0[length][i]);
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
