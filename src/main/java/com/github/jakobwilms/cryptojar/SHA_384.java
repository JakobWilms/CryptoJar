package com.github.jakobwilms.cryptojar;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.BitSet;

public class SHA_384 extends SHA_2_B64 {

    //////////////
    // INSTANCE //
    //////////////

    private static final SHA_384 INSTANCE = new SHA_384();

    public static SHA_384 getInstance() {
        return INSTANCE;
    }

    private SHA_384() {}

    ///////////////
    // CONSTANTS //
    ///////////////

    private final long @NotNull [] _H384 = {
            0xcbbb9d5dc1059ed8L,
            0x629a292a367cd507L,
            0x9159015a3070dd17L,
            0x152fecd8f70e5939L,
            0x67332667ffc00b31L,
            0x8eb44a8768581511L,
            0xdb0c2e0d64f98fa7L,
            0x47b5481dbefa4fa4L
    };

    private final byte @NotNull [][] H384 = {
            ByteBuffer.allocate(8).putLong(_H384[0]).array(),
            ByteBuffer.allocate(8).putLong(_H384[1]).array(),
            ByteBuffer.allocate(8).putLong(_H384[2]).array(),
            ByteBuffer.allocate(8).putLong(_H384[3]).array(),
            ByteBuffer.allocate(8).putLong(_H384[4]).array(),
            ByteBuffer.allocate(8).putLong(_H384[5]).array(),
            ByteBuffer.allocate(8).putLong(_H384[6]).array(),
            ByteBuffer.allocate(8).putLong(_H384[7]).array()
    };

    @Override
    byte @NotNull [][][] initialHash(int length) {
        final byte[][][] H0 = new byte[length][8][];
        H0[0] = Arrays.copyOf(H384, H384.length);
        return H0;
    }

    @Override
    HashReturn finalValue(byte @NotNull [][][] H0, int length, final int truncate) {
        return new HashReturn.SHA_384_HashReturn(H0, length);
    }
}
