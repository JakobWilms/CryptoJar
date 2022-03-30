package com.github.jakobwilms.cryptojar;

import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class SHA3_String {

    public static final SHA3_String EMPTY_STRING = SHA3_String.zeros(0);

    private List<Boolean> string;

    public SHA3_String() {
        this(10);
    }

    public SHA3_String(int initSize) {
        this(new ArrayList<>(initSize));
    }

    public SHA3_String(final List<Boolean> string) {
        this.string = string;
    }

    public SHA3_String(Boolean... booleans) {
        this(Arrays.asList(booleans));
    }

    public boolean get(int index) {
        return string.get(index);
    }

    public void set(int index, boolean value) {
        string.set(index, value);
    }

    public SHA3_String add(boolean value) {
        string.add(value);
        return this;
    }

    public SHA3_String add(@NotNull SHA3_String value) {
        List<Boolean> list = new ArrayList<>();
        for (int i = 0; i < this.size(); i++) list.add(this.get(i));
        for (int i = 0; i < value.size(); i++) list.add(value.get(i));
        this.string = list;
        return this;
    }

    public int size() {
        return string.size();
    }

    public void trunc(int s) {
        List<Boolean> next = new ArrayList<>();
        for (int i = 0; i < s; i++) next.add(get(i));
        this.string = next;
    }

    public SHA3_String truncNew(int s) {
        List<Boolean> next = new ArrayList<>();
        for (int i = 0; i < s; i++) next.add(get(i));
        return new SHA3_String(next);
    }

    public SHA3_String xor(SHA3_String other) {
        for (int i = 0; i < this.size(); i++) this.set(i, this.get(i) ^ other.get(i));
        return this;
    }


    public List<Boolean> array() {
        return string;
    }

    public SHA3_String substring(int from, int to) {
        return new SHA3_String(array().subList(from, to));
    }

    public byte @NotNull [] toByteArray() {
        System.out.println(array());
        byte[] bytes = new byte[size() / 8];
        for (int i = 0; i < size() / 8; i++) {
            byte b = 0;
            for (int j = 0; j < 8; j++) if (get(8 * i + j)) b |= 1 << (7 - i);
            bytes[i] = b;
        }
        System.out.println(Arrays.toString(bytes));
        return bytes;
    }

    @Contract("_ -> new")
    public static @NotNull SHA3_String valueOf(@NotNull String booleans) {
        List<Boolean> booleanList = new ArrayList<>();
        if (booleans.length() == 0) return new SHA3_String(booleanList);
        for (int i = 0; i < booleans.length(); i++) {
            booleanList.add(fromChar(booleans.charAt(i)));
        }

        return new SHA3_String(booleanList);
    }

    public static @NotNull SHA3_String valueOf(byte @NotNull [] bytes) {
        List<Boolean> list = new ArrayList<>();
        for (int i = 0; i < bytes.length; i++)
            for (int j = 0; j < Byte.SIZE; j++) list.add((bytes[i] & Math.toIntExact(Math.round(Math.pow(2, j)))) != 0);

        return new SHA3_String(list);
    }

    @Contract("_ -> new")
    public static @NotNull SHA3_String zeros(int s) {
        return SHA3_String.valueOf("0".repeat(s));
    }

    public static boolean fromChar(char c) {
        if (c == '0') return false;
        if (c == '1') return true;
        throw new IllegalArgumentException("Illegal Character to convert!");
    }

    public static char toChar(boolean b) {
        return b ? '1' : '0';
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < size(); i++) builder.append(toChar(get(i)));
        return "SHA3_String{" +
                builder +
                "}";
    }
}
