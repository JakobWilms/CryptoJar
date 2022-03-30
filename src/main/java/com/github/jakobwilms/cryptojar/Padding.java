package com.github.jakobwilms.cryptojar;

public class Padding {

    private static final Padding INSTANCE = new Padding();

    public static Padding getInstance() {
        return INSTANCE;
    }

    private Padding() {}

    public SHA3_String pad(int x, int m) {
        int j = mod(-m - 2, x);
        return SHA3_String.valueOf("1").add(SHA3_String.zeros(j)).add(SHA3_String.valueOf("1"));
    }

    protected int mod(int m, int n) {
        return m >= 0 ? m % n : n - Math.abs(m) % n;
    }
}
