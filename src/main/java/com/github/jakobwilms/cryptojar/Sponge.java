package com.github.jakobwilms.cryptojar;

import org.jetbrains.annotations.NotNull;

import java.util.Arrays;

public class Sponge {

    private static final Sponge INSTANCE = new Sponge();

    public static Sponge getInstance() {
        return INSTANCE;
    }

    private Sponge() {}

    public SHA3_String sponge(SpongeFunction f, @NotNull Padding pad, int r, int b, @NotNull SHA3_String N, int d) {
        System.out.println(r);
        System.out.println(b);
        System.out.println(N);
        System.out.println(d);

        SHA3_String P = N.add(pad.pad(r, N.size()));
        int n = P.size() / r;
        int c = b - r;

        SHA3_String[] P0 = new SHA3_String[n];
        for (int i = 0; i < n; i++) P0[i] = P.substring(r * i, r * i + r);

        SHA3_String S = SHA3_String.zeros(b);
        for (int i = 0; i < n - 1; i++) {
            S = f.f(S.xor(P0[i].add(SHA3_String.zeros(c))));
        }

        return _sponge(S, r, d, f);
    }

    private SHA3_String _sponge(@NotNull SHA3_String S, int r, int d, SpongeFunction f) {
        SHA3_String Z = SHA3_String.EMPTY_STRING;
        Z.add(S.truncNew(r));
        if (d <= Z.size()) return Z.truncNew(d);
        System.out.println(S);
        return _sponge(f.f(S), r, d, f);
    }
}
