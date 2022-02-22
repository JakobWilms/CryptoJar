package com.github.jakobwilms.cryptojar;

import org.jetbrains.annotations.NotNull;

import java.util.ArrayList;
import java.util.List;

public class SHA3_String {

    private final List<Boolean> string;

    public SHA3_String() {
        this(10);
    }

    public SHA3_String(int initSize) {
        this(new ArrayList<>(initSize));
    }

    public SHA3_String(final List<Boolean> string) {
        this.string = string;
    }

    public boolean get(int index) {
        return string.get(index);
    }

    public void set(int index, boolean value) {
        string.set(index, value);
    }

    public void add(boolean value) {
        string.add(value);
    }

    public void add(@NotNull SHA3_String value) {
        for (int i = 0; i < value.size(); i++) string.add(value.get(i));
    }

    public int size() {
        return string.size();
    }

    public List<Boolean> array() {
        return string;
    }
}
