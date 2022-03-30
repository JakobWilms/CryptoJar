package com.github.jakobwilms.cryptojar;

import org.jetbrains.annotations.NotNull;

public class Keccac implements SpongeFunction {

    private static final Keccac INSTANCE = new Keccac();

    public static Keccac getInstance() {
        return INSTANCE;
    }

    private Keccac() {}

    public SHA3_String f(SHA3_String s) {
        return keccac_f(s);
    }

    public SHA3_String keccac_p(@NotNull SHA3_String s, int nr) {
        final int w = w(s.size());
        final int l = l(s.size());
        SHA3_State state = SHA3_State.valueOf(s, w, l);
        for (int ir = 12 + 2 * l - nr; ir < 12 + 2 * l - 1; ir++) state.rnd(ir);
        return state.toSHAString();
    }

    public SHA3_String keccac_f(@NotNull SHA3_String s) {
        return keccac_p(s, 12 + 2 * l(s.size()));
    }

    public SHA3_String keccac_c(int c, @NotNull SHA3_String N, int d) {
        return Sponge.getInstance().sponge(Keccac.getInstance(), Padding.getInstance(), 1600 - c, 1600, N, d);
    }

    public int w(int b) {
        return b / 25;
    }

    public int l(int b) {
        return switch (w(b)) {
            case 1 -> 0;
            case 2 -> 1;
            case 4 -> 2;
            case 8 -> 3;
            case 16 -> 4;
            case 32 -> 5;
            case 64 -> 6;
            default -> -1;
        };
    }

}
