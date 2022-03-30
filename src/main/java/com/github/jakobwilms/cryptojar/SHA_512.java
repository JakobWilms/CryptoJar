package com.github.jakobwilms.cryptojar;

import org.jetbrains.annotations.NotNull;

import java.util.Arrays;

public class SHA_512 extends SHA_2_B64 {

    //////////////
    // INSTANCE //
    //////////////

    private static final SHA_512 INSTANCE = new SHA_512();

    private SHA_512() {
    }

    public static SHA_512 getInstance() {
        return INSTANCE;
    }

    @Override
    byte @NotNull [][][] initialHash(int length) {
        final byte[][][] H0 = new byte[length][8][];
        H0[0] = Arrays.copyOf(H512, H512.length);
        return H0;
    }

    @Override
    SHA2_Return finalValue(byte @NotNull [][][] H0, int length, final int truncate) {
        return new SHA2_Return.SHA_512_HashReturn(H0, length);
    }
}
