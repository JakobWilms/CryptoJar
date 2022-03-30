package com.github.jakobwilms.cryptojar;

import org.jetbrains.annotations.NotNull;

import java.util.BitSet;

public abstract class HashReturn {

    protected byte[] hashedBytes;

    public HashReturn() {
        this.hashedBytes = null;
    }

    abstract byte @NotNull [] calculateHashedBytes();

    public byte @NotNull [] hashedBytes() {
        if (hashedBytes != null) return hashedBytes;
        this.hashedBytes = calculateHashedBytes();
        return hashedBytes;
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
