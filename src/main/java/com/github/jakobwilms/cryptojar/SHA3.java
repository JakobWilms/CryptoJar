package com.github.jakobwilms.cryptojar;

import org.jetbrains.annotations.NotNull;

public class SHA3 extends HashAlgorithm {

    ///////////////
    // INSTANCES //
    ///////////////

    private static final SHA3 SHA3_224 = new SHA3(448, 224);
    private static final SHA3 SHA3_256 = new SHA3(512, 256);
    private static final SHA3 SHA3_384 = new SHA3(768, 768);
    private static final SHA3 SHA3_512 = new SHA3(1024, 1024);

    public static SHA3 getSha3_224() {return SHA3_224;}

    public static SHA3 getSha3_256() {return SHA3_256;}

    public static SHA3 getSha3_384() {return SHA3_384;}

    public static SHA3 getSha3_512() {return SHA3_512;}


    private final int c;
    private final int d;

    private SHA3(int c, int d) {
        this.c = c;
        this.d = d;
    }

    @Override
    public SHA3_Return hash(byte @NotNull [] bytes, int truncate) {
        return new SHA3_Return(Keccac.getInstance().keccac_c(c, SHA3_String.valueOf(bytes).add(false).add(true), d));
    }


}
