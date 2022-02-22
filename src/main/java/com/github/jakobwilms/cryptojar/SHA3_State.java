package com.github.jakobwilms.cryptojar;

import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;

import java.util.Arrays;

public class SHA3_State {


    private final int w;
    private boolean[][][] A;

    public SHA3_State(final int w) {
        this(w, new boolean[5][5][w]);
    }

    public SHA3_State(final int w, final boolean @NotNull [][][] A) {
        this.w = w;
        this.A = new boolean[A.length][][];
        for (int i = 0; i < A.length; i++)
            for (int j = 0; j < A[j].length; j++) A[i][j] = Arrays.copyOf(A[i][j], A[i][j].length);
    }

    @Contract("_, _ -> new")
    public static @NotNull SHA3_State valueOf(SHA3_String string, int w) {
        final boolean[][][] A = new boolean[5][5][w];
        for (int x = 0; x < 5; x++)
            for (int y = 0; y < 5; y++)
                for (int z = 0; z < w; z++) A[x][y][z] = string.get(w * (5 * y + x) + z);
        return new SHA3_State(w, A);
    }

    public void theta() {
        final boolean[][] C = new boolean[5][w];
        final boolean[][] D = new boolean[5][w];
        final boolean[][][] A1 = new boolean[5][5][w];
        for (int x = 0; x < 5; x++) {
            C[x] = new boolean[w];
            for (int z = 0; z < w; z++) {
                C[x][z] = A[x][0][z] ^ A[x][1][z] ^ A[x][2][z] ^ A[x][3][z] ^ A[x][4][z];
            }
        }
        for (int x = 0; x < 5; x++) {
            D[x] = new boolean[w];
            for (int z = 0; z < w; z++) {
                D[x][z] = C[mod(x - 1, 5)][z] ^ C[(x + 1) % 5][mod(z - 1, w)];
            }
        }
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                for (int z = 0; z < w; z++) {
                    A1[x][y][z] = A[x][y][z] ^ D[x][z];
                }
            }
        }

        this.A = A1;
    }

    public void rho() {
        final boolean[][][] A1 = new boolean[5][5][w];
        System.arraycopy(A[0][0], 0, A1[0][0], 0, w);
        int x = 1, y = 0;
        for (int t = 0; t < 24; t++) {
            for (int z = 0; z < w; z++) {
                A1[x][y][z] = A[x][y][mod(z - (t + 1) * (t + 2) / 2, w)];
                int tmp = y;
                y = (2 * x + 3 * y) % 5;
                x = tmp;
            }
        }

        this.A = A1;
    }

    public int mod(int m, int n) {
        return m >= 0 ? m % n : n - Math.abs(m) % n;
    }

    public SHA3_String toSHAString() {
        final SHA3_String[][] lanes = new SHA3_String[5][5];
        for (int i = 0; i < 5; i++)
            for (int j = 0; j < 5; j++) {
                lanes[i][j] = new SHA3_String(w);
                for (int z = 0; z < w; z++) lanes[i][j].add(A[i][j][z]);
            }
        final SHA3_String[] planes = new SHA3_String[5];
        for (int j = 0; j < 5; j++) {
            planes[j] = new SHA3_String(5 * w);
            for (int i = 0; i < 5; i++) planes[j].add(lanes[i][j]);
        }
        final SHA3_String sha3_string = new SHA3_String(25 * w);
        for (int i = 0; i < 5; i++) sha3_string.add(planes[i]);

        return sha3_string;
    }
}
