package com.github.jakobwilms.cryptojar;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.BitSet;

public class SHA_512_T extends SHA_2_B64 {

    //////////////
    // INSTANCE //
    //////////////

    private static final SHA_512_T INSTANCE = new SHA_512_T();

    public static SHA_512_T getInstance() {
        return INSTANCE;
    }

    private SHA_512_T() {}

    ///////////////
    // CONSTANTS //
    ///////////////

    private final long @NotNull [] _H512 = {
            0x6a09e667f3bcc908L,
            0xbb67ae8584caa73bL,
            0x3c6ef372fe94f82bL,
            0xa54ff53a5f1d36f1L,
            0x510e527fade682d1L,
            0x9b05688c2b3e6c1fL,
            0x1f83d9abfb41bd6bL,
            0x5be0cd19137e2179L,
    };

    private final byte @NotNull [][] H512 = {
            ByteBuffer.allocate(8).putLong(_H512[0]).array(),
            ByteBuffer.allocate(8).putLong(_H512[1]).array(),
            ByteBuffer.allocate(8).putLong(_H512[2]).array(),
            ByteBuffer.allocate(8).putLong(_H512[3]).array(),
            ByteBuffer.allocate(8).putLong(_H512[4]).array(),
            ByteBuffer.allocate(8).putLong(_H512[5]).array(),
            ByteBuffer.allocate(8).putLong(_H512[6]).array(),
            ByteBuffer.allocate(8).putLong(_H512[7]).array()
    };

    @Override
    public SHA2_Return hash(byte @NotNull [] bytes, final int truncate) {
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
        byte[][][] H0_2 = new byte[length][8][];
        byte[] n = ByteBuffer.allocate(8).putLong(0xa5a5a5a5a5a5a5a5L).array();
        final BitwiseOperator operator = new BitwiseOperator();

        for (int i = 0; i < 8; i++) H0_2[0][i] = operator.set(H512[i]).xor(n).getBytes();

        return H0_2;
    }

    @Override
    SHA2_Return finalValue(byte @NotNull [][][] H0, int length, final int truncate) {
        return new SHA2_Return.SHA_512_T_HashReturn(H0, length, truncate);
    }
}
