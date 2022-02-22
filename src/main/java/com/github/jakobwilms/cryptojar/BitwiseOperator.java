package com.github.jakobwilms.cryptojar;

import org.jetbrains.annotations.NotNull;

import java.math.BigInteger;
import java.nio.ByteBuffer;

public class BitwiseOperator {

    /////////////
    // FIELDS //
    ////////////

    private final boolean integer;
    private long value;

    ///////////////////
    // CONSTRUCTORS //
    //////////////////

    public BitwiseOperator() {
        this(0);
    }

    public BitwiseOperator(final long value) {
        this(value, false);
    }

    public BitwiseOperator(final long value, final boolean integer) {
        this.value = value;
        this.integer = integer;
    }

    /////////////
    // METHODS //
    /////////////

    public BitwiseOperator add(long value) {
        if (isInteger()) value = Math.toIntExact(value);
        else if (get() > Long.MAX_VALUE - value)
            return set(BigInteger.valueOf(value).add(BigInteger.valueOf(get())).mod(BigInteger.valueOf(Math.round(Math.pow(2, 64)))).longValue());

        return set(get() + value);
    }

    public BitwiseOperator add(@NotNull final BitwiseOperator value) {
        return add(value.get());
    }

    public BitwiseOperator add(final byte @NotNull [] value) {
        return value.length <= 4 ? add(ByteBuffer.wrap(value).getInt()) : add(ByteBuffer.wrap(value).getLong());
    }

    public BitwiseOperator complement() {
        if (isInteger()) return set(~((int) get()));
        return set(~get());
    }

    public BitwiseOperator xor(long value) {
        if (isInteger()) {
            value = Math.toIntExact(value);
            return set((int) get() ^ (int) value);
        }
        return set(get() ^ value);
    }

    public BitwiseOperator xor(@NotNull final BitwiseOperator value) {
        return xor(value.get());
    }

    public BitwiseOperator xor(final byte @NotNull [] value) {
        return value.length <= 4 ? xor(ByteBuffer.wrap(value).getInt()) : xor(ByteBuffer.wrap(value).getLong());
    }

    public BitwiseOperator or(long value) {
        if (isInteger()) {
            value = Math.toIntExact(value);
            return set((int) get() | (int) value);
        }
        return set(get() | value);
    }

    public BitwiseOperator or(@NotNull final BitwiseOperator value) {
        return or(value.get());
    }

    public BitwiseOperator or(final byte @NotNull [] value) {
        return value.length <= 4 ? or(ByteBuffer.wrap(value).getInt()) : or(ByteBuffer.wrap(value).getLong());
    }

    public BitwiseOperator and(long value) {
        if (isInteger()) {
            value = Math.toIntExact(value);
            return set((int) get() & (int) value);
        }
        return set(get() & value);
    }

    public BitwiseOperator and(@NotNull BitwiseOperator value) {
        return and(value.get());
    }

    public BitwiseOperator and(final byte @NotNull [] value) {
        return value.length <= 4 ? and(ByteBuffer.wrap(value).getInt()) : and(ByteBuffer.wrap(value).getLong());
    }

    public BitwiseOperator shift(final int shift) {
        if (shift == 0) return this;
        if (isInteger()) {
            if (shift > 0) return set(((int) get()) >>> shift);
            int cache = ((int) get()) << -shift;
            return set(cache);
        } else {
            if (shift > 0) return set(get() >>> shift);
            return set(get() << -shift);
        }
    }

    public BitwiseOperator rotate(final int rotate) {
        if (rotate == 0) return this;

        final int size = isInteger() ? 32 : 64;
        if (rotate > size) throw new IllegalArgumentException(String.format("Rotation Must Be Smaller Than %x", size));

        return new BitwiseOperator(get(), isInteger())
                .shift(rotate > 0 ? rotate - size : rotate + size)
                .or(shift(rotate));
    }

    public BitwiseOperator capitalSigma256_0() {
        final long value = get();
        return rotate(2)
                .xor(new BitwiseOperator(value, isInteger()).rotate(13))
                .xor(new BitwiseOperator(value, isInteger()).rotate(22));
    }

    public BitwiseOperator capitalSigma256_1() {
        final long value = get();
        return rotate(6)
                .xor(new BitwiseOperator(value, isInteger()).rotate(11))
                .xor(new BitwiseOperator(value, isInteger()).rotate(25));
    }

    public BitwiseOperator capitalSigma512_0() {
        final long value = get();
        return rotate(28)
                .xor(new BitwiseOperator(value, isInteger()).rotate(34))
                .xor(new BitwiseOperator(value, isInteger()).rotate(39));
    }

    public BitwiseOperator capitalSigma512_1() {
        final long value = get();
        return rotate(14)
                .xor(new BitwiseOperator(value, isInteger()).rotate(18))
                .xor(new BitwiseOperator(value, isInteger()).rotate(41));
    }

    public BitwiseOperator smallSigma256_0() {
        final long value = get();
        return rotate(7)
                .xor(new BitwiseOperator(value, isInteger()).rotate(18))
                .xor(new BitwiseOperator(value, isInteger()).shift(3));
    }

    public BitwiseOperator smallSigma256_1() {
        final long value = get();
        return rotate(17)
                .xor(new BitwiseOperator(value, isInteger()).rotate(19))
                .xor(new BitwiseOperator(value, isInteger()).shift(10));
    }

    public BitwiseOperator smallSigma512_0() {
        final long value = get();
        return rotate(1)
                .xor(new BitwiseOperator(value, isInteger()).rotate(8))
                .xor(new BitwiseOperator(value, isInteger()).shift(7));
    }

    public BitwiseOperator smallSigma512_1() {
        final long value = get();
        return rotate(19)
                .xor(new BitwiseOperator(value, isInteger()).rotate(61))
                .xor(new BitwiseOperator(value, isInteger()).shift(6));
    }

    public BitwiseOperator ch(final long a, final long b) {
        final long value = get();
        return and(a)
                .xor(new BitwiseOperator(value, isInteger())
                        .complement().and(b));
    }

    public BitwiseOperator ch(final byte @NotNull [] a, final byte @NotNull [] b) {
        return a.length <= 4 ? ch(ByteBuffer.wrap(a).getInt(), ByteBuffer.wrap(b).getInt()) : ch(ByteBuffer.wrap(a).getLong(), ByteBuffer.wrap(b).getLong());
    }

    public BitwiseOperator maj(final long a, final long b) {
        final long value = get();
        return and(a)
                .xor(new BitwiseOperator(value, isInteger()).and(b))
                .xor(new BitwiseOperator(a, isInteger()).and(b));
    }

    public BitwiseOperator maj(final byte @NotNull [] a, final byte @NotNull [] b) {
        return a.length <= 4 ? maj(ByteBuffer.wrap(a).getInt(), ByteBuffer.wrap(b).getInt()) : maj(ByteBuffer.wrap(a).getLong(), ByteBuffer.wrap(b).getLong());
    }

    public boolean isInteger() {
        return integer;
    }

    public long get() {
        return value;
    }

    public byte @NotNull [] getBytes() {
        return isInteger() ? ByteBuffer.allocate(4).putInt((int) get()).array() : ByteBuffer.allocate(8).putLong(get()).array();
    }

    public BitwiseOperator set(long value) {
        if (isInteger()) value = value % Math.round(Math.pow(2, 32));
        this.value = value;

        return this;
    }

    public BitwiseOperator set(final byte @NotNull [] value) {
        return value.length <= 4 ? set(ByteBuffer.wrap(value).getInt()) : set(ByteBuffer.wrap(value).getLong());
    }

    public BitwiseOperator parity(final byte @NotNull [] a, final byte @NotNull [] b) {
        return xor(a).xor(b);
    }

    public BitwiseOperator f(final int t, final byte @NotNull [] a, final byte @NotNull [] b) {
        if (t < 20) return ch(a, b);
        if (t < 40) return parity(a, b);
        if (t < 60) return maj(a, b);
        return parity(a, b);
    }
}
