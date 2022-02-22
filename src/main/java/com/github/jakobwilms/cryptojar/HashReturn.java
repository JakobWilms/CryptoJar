package com.github.jakobwilms.cryptojar;

import org.jetbrains.annotations.NotNull;

import java.util.BitSet;

public abstract class HashReturn {

    public static class SHA_1_HashReturn extends HashReturn {
        public SHA_1_HashReturn(byte @NotNull [][][] H0, int length) {super(H0, length, 256, 5, 32);}
    }

    public static class SHA_224_HashReturn extends HashReturn {
        public SHA_224_HashReturn(byte @NotNull [][][] H0, int length) {super(H0, length, 224, 7, 32);}
    }

    public static class SHA_256_HashReturn extends HashReturn {
        public SHA_256_HashReturn(byte @NotNull [][][] H0, int length) {super(H0, length, 256, 8, 32);}
    }

    public static class SHA_384_HashReturn extends HashReturn {
        public SHA_384_HashReturn(byte @NotNull [][][] H0, int length) {super(H0, length, 384, 6, 64);}
    }

    public static class SHA_512_HashReturn extends HashReturn {
        public SHA_512_HashReturn(byte @NotNull [][][] H0, int length) {super(H0, length, 512, 8, 64);}
    }

    public static class SHA_512_T_HashReturn extends HashReturn {
        public SHA_512_T_HashReturn(byte @NotNull [][][] H0, int length, final int truncate) {super(H0, length, truncate, truncate / 64, 64);}
    }


    private final byte @NotNull [][][] H0;
    protected final int length;
    private final int nBits;
    private final int repeatConcat;
    private final int repeat;

    private byte[] hashedBytes;

    public HashReturn(final byte @NotNull [][][] H0, final int length, final int nBits, final int repeatConcat, final int repeat) {
        this.H0 = H0;
        this.length = length;
        this.nBits = nBits;
        this.repeatConcat = repeatConcat;
        this.repeat = repeat;
        this.hashedBytes = null;
    }

    private byte @NotNull [] calculateHashedBytes() {
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

    public byte @NotNull [] hashedBytes() {
        if (hashedBytes != null) return hashedBytes;
        return calculateHashedBytes();
    }

    public @NotNull String hashedHex() {
        if (hashedBytes == null) hashedBytes();

        StringBuilder hashedHex = new StringBuilder(2 * hashedBytes.length);
        for (byte hashedByte : hashedBytes) {
            String hex = Integer.toHexString(0xff & hashedByte);
            if (hex.length() == 1) hashedHex.append('0');
            hashedHex.append(hex);
        }

        return hashedHex.toString();
    }

    public @NotNull BitSet hashedBitSet() {
        return BitSet.valueOf(hashedBytes());
    }

    public @NotNull String hashedBinary() {
        if (hashedBytes == null) hashedBytes();

        final BitSet bitSet = hashedBitSet();
        StringBuilder hashedBinary = new StringBuilder(hashedBytes.length * Byte.SIZE);
        for (int i = 0; i < hashedBytes.length * 8; i++) {
            char binary = bitSet.get(i) ? '1' : '0';
            hashedBinary.append(binary);
        }

        return hashedBinary.toString();
    }

    @Override
    public String toString() {
        return hashedHex();
    }
}
