package com.github.jakobwilms.cryptojar;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.jetbrains.annotations.Range;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.BitSet;

@SuppressWarnings("SuspiciousNameCombination")
public class ByteOperator {

    private byte @Nullable [] bytes;

    public ByteOperator() {
        this.bytes = null;
    }

    public ByteOperator(byte[] bytes) {
        this.bytes = Arrays.copyOf(bytes, bytes.length);
    }

    public ByteOperator trimTo(final int bytes) {
        checkState();

        final byte[] y = new byte[bytes];
        if (get().length == bytes) return this;
        else if (get().length > bytes) for (int i = 0; i < bytes; i++) y[i] = get()[get().length - i - 1];
        else for (int i = 0; i < bytes; i++) y[i] = (bytes - i) > get().length ? 0 : get()[get().length - bytes + i];
        set(y);
        return this;
    }

    public ByteOperator add(final byte @NotNull [] x) {
        checkState();

        if (get().length > 4)
            set(ByteBuffer
                    .allocate(8)
                    .putLong(ByteBuffer.wrap(get()).getLong() + ByteBuffer.wrap(x).getLong()).
                    array());
        else
            set(ByteBuffer
                    .allocate(4)
                    .putInt(Math.toIntExact(Math.round((ByteBuffer.wrap(get()).getInt() + ByteBuffer.wrap(x).getInt()) % Math.pow(2, 32))))
                    .array());
        return this;
    }

    public ByteOperator complement() {
        checkState();

        final int currentLength = length();
        final BitSet set = BitSet.valueOf(get());

        set.flip(0, get().length * 8);
        set(set.toByteArray());
        return trimTo(currentLength);
    }

    public ByteOperator xor(final byte @NotNull [] x) {
        checkState();

        final int currentLength = length();
        final BitSet set = BitSet.valueOf(get());

        set.xor(BitSet.valueOf(x));
        set(set.toByteArray());
        return trimTo(currentLength);
    }

    public ByteOperator or(final byte @NotNull [] x) {
        checkState();

        final int currentLength = length();
        final BitSet set = BitSet.valueOf(get());

        set.or(BitSet.valueOf(x));
        set(set.toByteArray());
        return trimTo(currentLength);
    }

    @SuppressWarnings("UnusedReturnValue")
    public ByteOperator and(final byte @NotNull [] x) {
        checkState();

        final int currentLength = length();
        final BitSet set = BitSet.valueOf(get());

        set.and(BitSet.valueOf(x));

        set(set.toByteArray());
        return trimTo(currentLength);
    }

    public ByteOperator shift(final int shift) {
        checkState();

        if (shift == 0) return this;

        final int currentLength = length();
        final BitSet set = BitSet.valueOf(get());
        final BitSet newSet = new BitSet();

        if (shift > 0) for (int i = shift; i < length() * 8; i++) newSet.set(i, set.get(i - shift));
        else for (int i = length() * 8; i > Math.abs(shift); i--) newSet.set(i - Math.abs(shift), set.get(i));

        set(newSet.toByteArray());
        return trimTo(currentLength);
    }

    public ByteOperator rotate(final int rotate) {
        checkState();

        if (rotate == 0) return this;

        final ByteOperator temp = new ByteOperator(get());
        if (rotate > 0) {
            temp.shift(-(length() - rotate));
            return shift(rotate).or(temp.get());
        } else {
            temp.shift(length() - rotate);
            return shift(-rotate).or(temp.get());
        }
    }

    public ByteOperator capitalSigma256_0() {
        final ByteOperator a = new ByteOperator(get());
        final ByteOperator b = new ByteOperator(get());

        a.rotate(13);
        b.rotate(22);

        return rotate(2).xor(a.get()).xor(b.get());
    }

    public ByteOperator capitalSigma256_1() {
        final ByteOperator a = new ByteOperator(get());
        final ByteOperator b = new ByteOperator(get());

        a.rotate(11);
        b.rotate(25);

        return rotate(6).xor(a.get()).xor(b.get());
    }

    public ByteOperator capitalSigma512_0() {
        final ByteOperator a = new ByteOperator(get());
        final ByteOperator b = new ByteOperator(get());

        a.rotate(34);
        b.rotate(39);

        return rotate(28).xor(a.get()).xor(b.get());
    }

    public ByteOperator capitalSigma512_1() {
        final ByteOperator a = new ByteOperator(get());
        final ByteOperator b = new ByteOperator(get());

        a.rotate(18);
        b.rotate(41);

        return rotate(14).xor(a.get()).xor(b.get());
    }
    public ByteOperator smallSigma256_0() {
        final ByteOperator a = new ByteOperator(get());
        final ByteOperator b = new ByteOperator(get());

        a.rotate(18);
        b.shift(3);

        return rotate(7).xor(a.get()).xor(b.get());
    }

    public ByteOperator smallSigma256_1() {
        final ByteOperator a = new ByteOperator(get());
        final ByteOperator b = new ByteOperator(get());

        a.rotate(19);
        b.shift(10);

        return rotate(17).xor(a.get()).xor(b.get());
    }

    public ByteOperator smallSigma512_0() {
        final ByteOperator a = new ByteOperator(get());
        final ByteOperator b = new ByteOperator(get());

        a.rotate(8);
        b.shift(7);

        return rotate(1).xor(a.get()).xor(b.get());
    }

    public ByteOperator smallSigma512_1() {
        final ByteOperator a = new ByteOperator(get());
        final ByteOperator b = new ByteOperator(get());

        a.rotate(61);
        b.shift(6);

        return rotate(19).xor(a.get()).xor(b.get());
    }

    public ByteOperator ch(final byte @NotNull [] x, final byte @NotNull [] y) {
        final ByteOperator a = new ByteOperator(get());
        final ByteOperator b = new ByteOperator(x);

        a.and(x);
        b.complement().and(y);

        return a.xor(b.get());
    }

    public ByteOperator maj(final byte @NotNull [] x, final byte @NotNull [] y) {
        final ByteOperator a = new ByteOperator(get());
        final ByteOperator b = new ByteOperator(get());
        final ByteOperator c = new ByteOperator(x);

        a.and(x);
        b.and(y);
        c.and(y);

        return a.xor(b.get()).xor(c.get());
    }

    public ByteOperator parity(final byte @NotNull [] x, final byte @NotNull [] y) {
        return xor(x).xor(y);
    }

    public ByteOperator f(@Range(from = 0, to = 79) final int t, final byte @NotNull [] x, final byte @NotNull [] y) {
        if (t < 20) return ch(x, y);
        else if (t < 40) return parity(x, y);
        else if (t < 60) return maj(x, y);
        else return parity(x, y);
    }

    private void checkState() {
        if (this.bytes == null)
            throw new NullPointerException("Can not invoke any method on null array!");
    }

    public int length() {
        return get().length;
    }

    public ByteOperator set(byte[] bytes) {
        this.bytes = Arrays.copyOf(bytes, bytes.length);
        return this;
    }

    public byte[] get() {
        return bytes;
    }

    @Override
    public String toString() {
        return Arrays.toString(get());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ByteOperator that)) return false;
        return Arrays.equals(bytes, that.bytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }
}
