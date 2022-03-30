package com.github.jakobwilms.cryptojar;

import org.jetbrains.annotations.NotNull;

import java.util.Arrays;

public class SHA_256 extends SHA_2_B32 {

    //////////////
    // INSTANCE //
    //////////////

    private static final SHA_256 INSTANCE = new SHA_256();

    private SHA_256() {}

    public static SHA_256 getInstance() {
        return INSTANCE;
    }

    @Override
    byte @NotNull [][][] initialHash(int length) {
        byte[][][] H0 = new byte[length][8][];
        H0[0] = Arrays.copyOf(H256, H256.length);
        return H0;
    }

    @Override
    @NotNull SHA2_Return finalValue(final byte @NotNull [][][] H0, final int length) {
        return new SHA2_Return.SHA_256_HashReturn(H0, length);
    }
}
