package com.github.jakobwilms.cryptojar;

import org.jetbrains.annotations.NotNull;

import java.util.BitSet;

public class SHA2_Return extends HashReturn {

    public static class SHA_1_HashReturn extends SHA2_Return {
        public SHA_1_HashReturn(byte @NotNull [][][] H0, int length) {super(H0, length, 256, 5, 32);}
    }

    public static class SHA_224_HashReturn extends SHA2_Return {
        public SHA_224_HashReturn(byte @NotNull [][][] H0, int length) {super(H0, length, 224, 7, 32);}
    }

    public static class SHA_256_HashReturn extends SHA2_Return {
        public SHA_256_HashReturn(byte @NotNull [][][] H0, int length) {super(H0, length, 256, 8, 32);}
    }

    public static class SHA_384_HashReturn extends SHA2_Return {
        public SHA_384_HashReturn(byte @NotNull [][][] H0, int length) {super(H0, length, 384, 6, 64);}
    }

    public static class SHA_512_HashReturn extends SHA2_Return {
        public SHA_512_HashReturn(byte @NotNull [][][] H0, int length) {super(H0, length, 512, 8, 64);}
    }

    public static class SHA_512_T_HashReturn extends SHA2_Return {
        public SHA_512_T_HashReturn(byte @NotNull [][][] H0, int length, final int truncate) {super(H0, length, truncate, truncate / 64, 64);}
    }


    private final byte @NotNull [][][] H0;
    private final int length;
    private final int nBits;
    private final int repeatConcat;
    private final int repeat;

    public SHA2_Return(final byte @NotNull [][][] H0, final int length, final int nBits, final int repeatConcat, final int repeat) {
        super();
        this.H0 = H0;
        this.length = length;
        this.nBits = nBits;
        this.repeatConcat = repeatConcat;
        this.repeat = repeat;
    }

    @Override
    public byte @NotNull [] calculateHashedBytes() {
        BitSet set = new BitSet(nBits);
        for (int i = 0; i < repeatConcat; i++) {
            BitSet subSet = BitSet.valueOf(H0[length][i]);
            for (int j = 0; j < repeat; j++) {
                set.set(i * repeat + j, subSet.get(j));
            }
        }
        this.hashedBytes = set.toByteArray();

        return hashedBytes;
    }
}
