package com.github.jakobwilms.cryptojar;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.nio.ByteBuffer;
import java.util.BitSet;

public abstract class SHA_2_B64 extends HashAlgorithm {

    ///////////////
    // CONSTANTS //
    ///////////////

    private final long @NotNull [] K512 = {
            0x428a2f98d728ae22L, 0x7137449123ef65cdL, 0xb5c0fbcfec4d3b2fL, 0xe9b5dba58189dbbcL,
            0x3956c25bf348b538L, 0x59f111f1b605d019L, 0x923f82a4af194f9bL, 0xab1c5ed5da6d8118L,
            0xd807aa98a3030242L, 0x12835b0145706fbeL, 0x243185be4ee4b28cL, 0x550c7dc3d5ffb4e2L,
            0x72be5d74f27b896fL, 0x80deb1fe3b1696b1L, 0x9bdc06a725c71235L, 0xc19bf174cf692694L,
            0xe49b69c19ef14ad2L, 0xefbe4786384f25e3L, 0x0fc19dc68b8cd5b5L, 0x240ca1cc77ac9c65L,
            0x2de92c6f592b0275L, 0x4a7484aa6ea6e483L, 0x5cb0a9dcbd41fbd4L, 0x76f988da831153b5L,
            0x983e5152ee66dfabL, 0xa831c66d2db43210L, 0xb00327c898fb213fL, 0xbf597fc7beef0ee4L,
            0xc6e00bf33da88fc2L, 0xd5a79147930aa725L, 0x06ca6351e003826fL, 0x142929670a0e6e70L,
            0x27b70a8546d22ffcL, 0x2e1b21385c26c926L, 0x4d2c6dfc5ac42aedL, 0x53380d139d95b3dfL,
            0x650a73548baf63deL, 0x766a0abb3c77b2a8L, 0x81c2c92e47edaee6L, 0x92722c851482353bL,
            0xa2bfe8a14cf10364L, 0xa81a664bbc423001L, 0xc24b8b70d0f89791L, 0xc76c51a30654be30L,
            0xd192e819d6ef5218L, 0xd69906245565a910L, 0xf40e35855771202aL, 0x106aa07032bbd1b8L,
            0x19a4c116b8d2d0c8L, 0x1e376c085141ab53L, 0x2748774cdf8eeb99L, 0x34b0bcb5e19b48a8L,
            0x391c0cb3c5c95a63L, 0x4ed8aa4ae3418acbL, 0x5b9cca4f7763e373L, 0x682e6ff3d6b2b8a3L,
            0x748f82ee5defb2fcL, 0x78a5636f43172f60L, 0x84c87814a1f0ab72L, 0x8cc702081a6439ecL,
            0x90befffa23631e28L, 0xa4506cebde82bde9L, 0xbef9a3f7b2c67915L, 0xc67178f2e372532bL,
            0xca273eceea26619cL, 0xd186b8c721c0c207L, 0xeada7dd6cde0eb1eL, 0xf57d4f7fee6ed178L,
            0x06f067aa72176fbaL, 0x0a637dc5a2c898a6L, 0x113f9804bef90daeL, 0x1b710b35131c471bL,
            0x28db77f523047d84L, 0x32caab7b40c72493L, 0x3c9ebe0a15c9bebcL, 0x431d67c49c100d4cL,
            0x4cc5d4becb3e42b6L, 0x597f299cfc657e2aL, 0x5fcb6fab3ad6faecL, 0x6c44198c4a475817L
    };

    private final long @NotNull [] _H512 = {
            0x6a09e667f3bcc908L,
            0xbb67ae8584caa73bL,
            0x3c6ef372fe94f82bL,
            0xa54ff53a5f1d36f1L,
            0x510e527fade682d1L,
            0x9b05688c2b3e6c1fL,
            0x1f83d9abfb41bd6bL,
            0x5be0cd19137e2179L,
    };

    protected final byte @NotNull [][] H512 = {
            ByteBuffer.allocate(8).putLong(_H512[0]).array(),
            ByteBuffer.allocate(8).putLong(_H512[1]).array(),
            ByteBuffer.allocate(8).putLong(_H512[2]).array(),
            ByteBuffer.allocate(8).putLong(_H512[3]).array(),
            ByteBuffer.allocate(8).putLong(_H512[4]).array(),
            ByteBuffer.allocate(8).putLong(_H512[5]).array(),
            ByteBuffer.allocate(8).putLong(_H512[6]).array(),
            ByteBuffer.allocate(8).putLong(_H512[7]).array()
    };

    @Override
    public HashReturn hash(byte @NotNull [] bytes, final int truncate) {
        BitSet[] bitSets = preprocess(BitSet.valueOf(bytes), bytes.length * 8);
        return finalValue(compute(bitSets, truncate, null), bitSets.length, -1);
    }

    @Override
    BitSet @NotNull [] preprocess(@NotNull BitSet bitSet, int size) {
        // PADDING
        bitSet.set(size, true);
        int bitsToAdd = 0;
        for (int i = 0; i < 1024; i++)
            if ((size + i + 1) % 1024 == 0) {
                bitsToAdd = i - 128;
                break;
            }
        final BitSet sizeSet = BitSet.valueOf(new long[]{size});
        final int lastSetBit = sizeSet.length();
        for (int i = 0; i < 128; i++) bitSet.set(size + bitsToAdd + 1 + 128 - lastSetBit + i, sizeSet.get(i));
        // PARSING
        final BitSet[] sets = new BitSet[(size + 1 + bitsToAdd + 128) / 1024];
        for (int i = 0; i < (size + 1 + bitsToAdd + 128) / 1024; i++) {
            sets[i] = bitSet.get(i * 1024, (i + 1) * 1024);
        }

        return sets;
    }

    byte @NotNull [][][] compute(final @NotNull BitSet @NotNull [] sets, final int truncate, byte @Nullable [][][] h0) {
        byte[][][] H0 = h0 == null ? initialHash(sets.length + 1) : h0;

        for (int i = 0; i < sets.length; i++) {
            final byte[][] w = new byte[80][8];
            BitwiseOperator op1 = new BitwiseOperator(), op2 = new BitwiseOperator(), op3 = new BitwiseOperator();
            for (int t = 0; t < 80; t++)
                w[t] = t < 16 ? trimTo(sets[i].get(t * 64, (t + 1) * 64).toByteArray(), 8) :
                        op1.set(w[t - 2]).smallSigma512_1().add(op2.set(w[t - 15]).smallSigma512_0()).add(w[t - 16]).getBytes();
            byte[] a = H0[i][0], b = H0[i][1],
                    c = H0[i][2], d = H0[i][3],
                    e = H0[i][4], f = H0[i][5],
                    g = H0[i][6], h = H0[i][7];

            for (int t = 0; t < 80; t++) {
                byte[] t1 = op1.set(h).add(op2.set(e).capitalSigma512_1())
                        .add(op3.set(e).ch(f, g))
                        .add(ByteBuffer.allocate(8).putLong(K512[t]).array())
                        .add(w[t]).getBytes();
                byte[] t2 = op1.set(a).capitalSigma512_0()
                        .add(op2.set(a).maj(b, c)).getBytes();
                h = g;
                g = f;
                f = e;
                e = op1.set(d).add(t1).getBytes();
                d = c;
                c = b;
                b = a;
                a = op1.set(t1).add(t2).getBytes();
            }

            H0[i + 1][0] = op1.set(a).add(H0[i][0]).getBytes();
            H0[i + 1][1] = op1.set(b).add(H0[i][1]).getBytes();
            H0[i + 1][2] = op1.set(c).add(H0[i][2]).getBytes();
            H0[i + 1][3] = op1.set(d).add(H0[i][3]).getBytes();
            H0[i + 1][4] = op1.set(e).add(H0[i][4]).getBytes();
            H0[i + 1][5] = op1.set(f).add(H0[i][5]).getBytes();
            H0[i + 1][6] = op1.set(g).add(H0[i][6]).getBytes();
            H0[i + 1][7] = op1.set(h).add(H0[i][7]).getBytes();
        }

        return H0;
    }

    abstract HashReturn finalValue(final byte @NotNull [][][] H0, final int length, final int truncate);

    abstract byte @NotNull [][][] initialHash(final int length);
}
