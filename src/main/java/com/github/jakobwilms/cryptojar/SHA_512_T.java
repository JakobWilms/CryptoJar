package com.github.jakobwilms.cryptojar;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.BitSet;

import static com.github.jakobwilms.cryptojar.SHA_Helper.*;

public class SHA_512_T extends SHA_3 {

    private static final SHA_512_T INSTANCE = new SHA_512_T();

    public static SHA_512_T getInstance() {
        return INSTANCE;
    }

    private SHA_512_T() {}

    @Override
    public String hash(byte @NotNull [] bytes, final int truncate) {
        if (truncate <= 0)
            throw new IllegalArgumentException(String.format("Truncate Size must be greater than 0, value is %d", truncate));
        if (truncate % 64 != 0)
            throw new IllegalArgumentException(String.format("Truncate Size must be 0 mod 64, value is %d", truncate));

        BitSet[] bitSets = preprocess(BitSet.valueOf(bytes), bytes.length * 8);
        final byte[][][] H0_2 = H0_2(bitSets.length + 1);
        final byte[][][] H0 = SHA_512.getInstance().compute(
                SHA_512.getInstance().preprocess(
                        BitSet.valueOf(("SHA-512/" + truncate).getBytes(StandardCharsets.UTF_8)),
                        ("SHA-512/" + truncate).getBytes(StandardCharsets.UTF_8).length * 8
                ), -1, H0_2);

        return finalValue(compute(bitSets, truncate, H0), bitSets.length, truncate);
    }

    @Override
    byte @NotNull [][][] initialHash(int length) {
        return new byte[0][][];
    }

    byte @NotNull [][][] H0_2(final int length) {
        byte[][] H0_1 = new byte[][]{
                toWBits(ByteBuffer.allocate(8).putLong(H512[0]).array(), 64),
                toWBits(ByteBuffer.allocate(8).putLong(H512[1]).array(), 64),
                toWBits(ByteBuffer.allocate(8).putLong(H512[2]).array(), 64),
                toWBits(ByteBuffer.allocate(8).putLong(H512[3]).array(), 64),
                toWBits(ByteBuffer.allocate(8).putLong(H512[4]).array(), 64),
                toWBits(ByteBuffer.allocate(8).putLong(H512[5]).array(), 64),
                toWBits(ByteBuffer.allocate(8).putLong(H512[6]).array(), 64),
                toWBits(ByteBuffer.allocate(8).putLong(H512[7]).array(), 64)
        };
        byte[][][] H0_2 = new byte[length][8][];
        byte[] n = ByteBuffer.allocate(8).putLong(0xa5a5a5a5a5a5a5a5L).array();
        for (int i = 0; i < 8; i++) {
            H0_2[0][i] = xor(H0_1[i], n);
        }

        return H0_2;
    }

    @Override
    String finalValue(byte @NotNull [][][] H0, int length, final int truncate) {
        BitSet set = new BitSet(truncate);
        for (int i = 0; i < truncate / 64; i++) {
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
