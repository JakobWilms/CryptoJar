package com.github.jakobwilms.cryptojar;

import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Range;

import java.nio.ByteBuffer;
import java.util.BitSet;

class SHA_Helper {

    static final int[] K1 = {
            0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,
            0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,
            0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,
            0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,
            0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc,
            0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc,
            0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6,
            0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6
    };

    /**
     * Constants used for SHA-224 and SHA-256 <br>
     * These numbers represent
     * the first 32 bits of the fractional parts of
     * the cube roots of the first 64 primes.
     */
    static final int[] K256 = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    /**
     * Constants used for SHA-384, SHA-512, SHA-512/224, SHA-512/256 <br>
     * These numbers represent
     * the first 64 bits of the fractional parts of
     * the cube roots of the first 80 primes.
     */
    static final long[] K512 = {
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

    static final int[] H1 = {
            0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
    };

    /**
     * The Initial Hash Value for SHA-256 <br>
     * These numbers represent
     * the first 32 bits of the fractional parts of
     * the square roots of the first 8 primes.
     */
    static final int[] H256 = {
            0x6a09e667, 0xbb67ae85,
            0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c,
            0x1f83d9ab, 0x5be0cd19
    };

    static final int[] H224 = {
            0xc1059ed8, 0x367cd507,
            0x3070dd17, 0xf70e5939,
            0xffc00b31, 0x68581511,
            0x64f98fa7, 0xbefa4fa4
    };

    static final long[] H384 = {
            0xcbbb9d5dc1059ed8L,
            0x629a292a367cd507L,
            0x9159015a3070dd17L,
            0x152fecd8f70e5939L,
            0x67332667ffc00b31L,
            0x8eb44a8768581511L,
            0xdb0c2e0d64f98fa7L,
            0x47b5481dbefa4fa4L
    };

    static final long[] H512 = {
            0x6a09e667f3bcc908L,
            0xbb67ae8584caa73bL,
            0x3c6ef372fe94f82bL,
            0xa54ff53a5f1d36f1L,
            0x510e527fade682d1L,
            0x9b05688c2b3e6c1fL,
            0x1f83d9abfb41bd6bL,
            0x5be0cd19137e2179L,
    };

    @Contract(pure = true)
    static byte @NotNull [] rotateRight(final int n, final byte @NotNull [] x) {
        final byte[] a = shiftRight(n, x);
        final byte[] b = shiftLeft(x.length - n, x);
        return or(a, b);
    }

    @Contract(pure = true)
    static byte @NotNull [] rotateLeft(int n, byte[] x) {
        byte[] a = shiftLeft(n, x);
        byte[] b = shiftRight(x.length - n, x);
        return or(a, b);
    }

    @Contract(pure = true)
    static byte @NotNull [] shiftRight(final int n, final byte @NotNull [] x) {
        final BitSet set = BitSet.valueOf(x);
        final BitSet y = new BitSet();
        for (int i = 0; i < x.length * 8 - n; i++) {
            y.set(i + x.length * 8 + n, set.get(i + x.length * 8));
        }
        return toWBits(y.toByteArray(), x.length * 8);
    }

    @Contract(pure = true)
    static byte @NotNull [] shiftLeft(int n, byte[] x) {
        BitSet set = BitSet.valueOf(x);
        BitSet y = new BitSet();
        for (int i = 0; i < x.length * 8; i++) {
            y.set(i + x.length * 8 - n, set.get(i + x.length * 8));
        }
        return toWBits(y.toByteArray(), x.length * 8);
    }

    @Contract(pure = true)
    static byte @NotNull [] and(final byte @NotNull [] x, final byte @NotNull [] y) {
        final BitSet x0 = BitSet.valueOf(x);
        final BitSet y0 = BitSet.valueOf(y);
        x0.and(y0);
        final byte[] z = x0.toByteArray();
        return toWBits(z, x.length * 8);
    }

    @Contract(pure = true)
    static byte @NotNull [] or(final byte @NotNull [] x, final byte @NotNull [] y) {
        final BitSet x0 = BitSet.valueOf(x);
        final BitSet y0 = BitSet.valueOf(y);
        x0.or(y0);
        final byte[] z = x0.toByteArray();
        return toWBits(z, x.length * 8);
    }

    @Contract(pure = true)
    static byte @NotNull [] xor(final byte @NotNull [] x, final byte @NotNull [] y) {
        BitSet x0 = BitSet.valueOf(x);
        BitSet y0 = BitSet.valueOf(y);
        x0.xor(y0);
        final byte[] z = x0.toByteArray();
        return toWBits(z, x.length * 8);
    }

    @Contract(pure = true)
    static byte @NotNull [] complement(final byte @NotNull [] x) {
        BitSet x0 = BitSet.valueOf(x);
        x0.flip(0, 64);
        final byte[] z = x0.toByteArray();
        return toWBits(z, x.length * 8);
    }

    @Contract(pure = true)
    static byte @NotNull [] add(final byte @NotNull [] x, final byte @NotNull [] y) {
        final int x0 = ByteBuffer.wrap(x).getInt();
        final int y0 = ByteBuffer.wrap(y).getInt();
        final int z = Math.toIntExact(Math.round((x0 + y0) % Math.pow(2, x.length * 8)));

        return ByteBuffer.allocate(x.length).putInt(z).array();
    }

    @Contract(pure = true)
    static byte @NotNull [] ch(final byte @NotNull [] x, final byte @NotNull [] y, final byte @NotNull [] z) {
        final byte[] a = and(x, y);
        final byte[] b = and(complement(x), z);

        return xor(a, b);
    }

    @Contract(pure = true)
    static byte @NotNull [] maj(final byte @NotNull [] x, final byte @NotNull [] y, final byte @NotNull [] z) {
        final byte[] a = and(x, y);
        final byte[] b = and(x, z);
        //noinspection SuspiciousNameCombination
        final byte[] c = and(y, z);

        return xor(xor(a, b), c);
    }

    @Contract(pure = true)
    static byte @NotNull [] parity(final byte @NotNull [] x, final byte @NotNull [] y, final byte @NotNull [] z) {
        return xor(xor(x, y), z);
    }

    @Contract(pure = true)
    static byte @NotNull [] f(@Range(from = 0, to = 79) final int t, final byte @NotNull [] x, final byte @NotNull [] y, final byte @NotNull [] z) {
        if (t < 20) return ch(x, y, z);
        else if (t < 40) return parity(x, y, z);
        else if (t < 60) return maj(x, y, z);
        else return parity(x, y, z);
    }

    @Contract(pure = true)
    static byte @NotNull [] capitalSigma256_0(final byte @NotNull [] x) {
        final byte[] a = rotateRight(2, x);
        final byte[] b = rotateRight(13, x);
        final byte[] c = rotateRight(22, x);

        return xor(xor(a, b), c);
    }

    @Contract(pure = true)
    static byte @NotNull [] capitalSigma256_1(final byte @NotNull [] x) {
        final byte[] a = rotateRight(6, x);
        final byte[] b = rotateRight(11, x);
        final byte[] c = rotateRight(25, x);

        return xor(xor(a, b), c);
    }

    @Contract(pure = true)
    static byte @NotNull [] capitalSigma512_0(final byte @NotNull [] x) {
        final byte[] a = rotateRight(28, x);
        final byte[] b = rotateRight(34, x);
        final byte[] c = rotateRight(39, x);

        return xor(xor(a, b), c);
    }

    @Contract(pure = true)
    static byte @NotNull [] capitalSigma512_1(final byte @NotNull [] x) {
        final byte[] a = rotateRight(14, x);
        final byte[] b = rotateRight(18, x);
        final byte[] c = rotateRight(41, x);

        return xor(xor(a, b), c);
    }

    @Contract(pure = true)
    static byte @NotNull [] smallSigma256_0(final byte @NotNull [] x) {
        final byte[] a = rotateRight(7, x);
        final byte[] b = rotateRight(18, x);
        final byte[] c = shiftRight(3, x);

        return xor(xor(a, b), c);
    }

    @Contract(pure = true)
    static byte @NotNull [] smallSigma256_1(final byte @NotNull [] x) {
        final byte[] a = rotateRight(17, x);
        final byte[] b = rotateRight(19, x);
        final byte[] c = shiftRight(10, x);

        return xor(xor(a, b), c);
    }

    @Contract(pure = true)
    static byte @NotNull [] smallSigma512_0(final byte @NotNull [] x) {
        final byte[] a = rotateRight(1, x);
        final byte[] b = rotateRight(8, x);
        final byte[] c = shiftRight(7, x);

        return xor(xor(a, b), c);
    }

    @Contract(pure = true)
    static byte @NotNull [] smallSigma512_1(final byte @NotNull [] x) {
        final byte[] a = rotateRight(19, x);
        final byte[] b = rotateRight(61, x);
        final byte[] c = shiftRight(6, x);

        return xor(xor(a, b), c);
    }

    @Contract(pure = true)
    static byte @NotNull [] toWBits(final byte @NotNull [] x, @Range(from = 8, to = Integer.MAX_VALUE) final int w) {
        final int bytes = w / 8;
        final byte[] y = new byte[bytes];
        if (x.length == bytes) return x;
        else if (x.length > bytes) for (int i = 0; i < bytes; i++) y[i] = x[x.length - i - 1];
        else for (int i = 0; i < bytes; i++) y[i] = (bytes - i) > x.length ? 0 : x[x.length - bytes + i];
        return y;
    }
}
