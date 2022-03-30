package com.github.jakobwilms.cryptojar;

import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;

import java.util.Arrays;

public class SHA3_State {


    private final int w;
    private final int l;
    private boolean[][][] A;

    public SHA3_State(final int w, final int l) {
        this(w, l, new boolean[5][5][w]);
    }

    public SHA3_State(final int w, final int l, final boolean @NotNull [][][] A) {
        this.w = w;
        this.l = l;
        this.A = new boolean[5][5][w];
        for (int i = 0; i < 5; i++)
            for (int k = 0; k < 5; k++) this.A[i][k] = Arrays.copyOf(A[i][k], A[i][k].length);
    }

    @Contract("_, _, _ -> new")
    public static @NotNull SHA3_State valueOf(SHA3_String string, int w, int l) {
        System.out.println(string);
        final boolean[][][] A = new boolean[5][5][w];
        for (int x = 0; x < 5; x++)
            for (int y = 0; y < 5; y++)
                for (int z = 0; z < w; z++) A[x][y][z] = string.get(w * (5 * y + x) + z);
        SHA3_State state = new SHA3_State(w, l, A);
        System.out.println(state);
        return state;
    }

    public SHA3_State theta() {
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
        return this;
    }

    public SHA3_State rho() {
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
        return this;
    }

    public SHA3_State pi() {
        final boolean[][][] A1 = new boolean[5][5][w];
        for (int x = 0; x < 5; x++)
            for (int y = 0; y < 5; y++)
                System.arraycopy(A[(x + 3 * y) % 5][x], 0, A1[x][y], 0, w);

        this.A = A1;
        return this;
    }

    public SHA3_State chi() {
        final boolean[][][] A1 = new boolean[5][5][w];
        for (int x = 0; x < 5; x++)
            for (int y = 0; y < 5; y++)
                for (int z = 0; z < w; z++) A1[x][y][z] = A[x][y][z] ^ ((!A[(x + 1) % 5][y][z]) & A[(x + 2) % 5][y][z]);

        this.A = A1;
        return this;
    }

    public boolean rc(int t) {
        if (t % 255 == 0) return true;
        SHA3_String r = SHA3_String.valueOf("10000000");
        for (int i = 1; i < t % 255; i++) {
            r = SHA3_String.valueOf("0").add(r);
            r.set(0, r.get(0) ^ r.get(8));
            r.set(4, r.get(4) ^ r.get(8));
            r.set(5, r.get(5) ^ r.get(8));
            r.set(6, r.get(6) ^ r.get(8));
            r.trunc(8);
        }

        return r.get(0);
    }

    public SHA3_State jota(int ir) {
        final boolean[][][] A1 = new boolean[5][5][w];
        for (int x = 0; x < 5; x++) for (int y = 0; y < 5; y++) System.arraycopy(A[x][y], 0, A1[x][y], 0, w);
        SHA3_String RC = SHA3_String.zeros(w);
        for (int j = 0; j < l; j++) RC.set(Math.toIntExact(Math.round(Math.pow(2, j) - 1)), rc(j + 7 * ir));
        for (int z = 0; z < w; z++) A1[0][0][z] = A1[0][0][z] ^ RC.get(z);

        this.A = A1;
        return this;
    }

    public SHA3_State rnd(int ir) {
        return this.theta().rho().pi().chi().jota(ir);
    }

    public int mod(int m, int n) {
        return m >= 0 ? m % n : Math.abs(m) % n != 0 ? n - Math.abs(m) % n : 0;
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

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                for (int z = 0; z < w; z++) {
                    builder.append(A[x][y][z] ? '1' : '0');
                }
            }
        }
        return "SHA3_State{" +
                "w=" + w +
                ", l=" + l +
                ", A=" + builder +
                '}';
    }
}
