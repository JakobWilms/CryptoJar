package com.github.jakobwilms.cryptojar;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class SHA_224 extends SHA_2_B32 {

    //////////////
    // INSTANCE //
    //////////////

    private static final SHA_224 INSTANCE = new SHA_224();

    public static SHA_224 getInstance() {
        return INSTANCE;
    }

    private SHA_224() {}

    ///////////////
    // CONSTANTS //
    ///////////////

    private final int @NotNull [] _H224 = {
            0xc1059ed8, 0x367cd507,
            0x3070dd17, 0xf70e5939,
            0xffc00b31, 0x68581511,
            0x64f98fa7, 0xbefa4fa4
    };

    private final byte @NotNull [][] H224 = {
            ByteBuffer.allocate(4).putInt(_H224[0]).array(),
            ByteBuffer.allocate(4).putInt(_H224[1]).array(),
            ByteBuffer.allocate(4).putInt(_H224[2]).array(),
            ByteBuffer.allocate(4).putInt(_H224[3]).array(),
            ByteBuffer.allocate(4).putInt(_H224[4]).array(),
            ByteBuffer.allocate(4).putInt(_H224[5]).array(),
            ByteBuffer.allocate(4).putInt(_H224[6]).array(),
            ByteBuffer.allocate(4).putInt(_H224[7]).array()
    };

    @Override
    byte @NotNull [][][] initialHash(int length) {
        byte[][][] H0 = new byte[length][8][];
        H0[0] = Arrays.copyOf(H224, H224.length);
        return H0;
    }

    @Override
    @NotNull SHA2_Return finalValue(byte @NotNull [][][] H0, int length) {
        return new SHA2_Return.SHA_224_HashReturn(H0, length);
    }
}
