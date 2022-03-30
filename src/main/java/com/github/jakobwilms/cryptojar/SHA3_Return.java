package com.github.jakobwilms.cryptojar;

import org.jetbrains.annotations.NotNull;

public class SHA3_Return extends HashReturn {

    private final SHA3_String string;

    public SHA3_Return(SHA3_String string) {
        this.string = string;
    }

    @Override
    public byte @NotNull [] calculateHashedBytes() {
        return string.toByteArray();
    }

}
