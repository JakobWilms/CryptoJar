package com.github.jakobwilms.cryptojar;

import org.jetbrains.annotations.NotNull;

import java.io.*;
import java.util.Locale;

public abstract class HashAlgorithm {

    /**
     * Single Private Constructor to prevent the default one from being generated
     */
    HashAlgorithm() {}

    /**
     * Hash a given array of bytes.
     * @param bytes The Array of bytes to hash
     *
     * @return The hashed Hex-Value
     */
    public abstract String hash(final byte @NotNull [] bytes);

    /**
     * Hash the bytes of a given InputStream. <br>
     * This method behaves exactly as calling <code>hash(stream.readAllBytes());</code>.
     * @param stream The InputStream to use
     *
     * @return The hashed Hex-Value
     *
     * @throws IOException When an Exception Occurs when reading the bytes from the stream
     */
    public String hash(final @NotNull InputStream stream) throws IOException {
        return hash(stream.readAllBytes());
    }

    /**
     * Hash the bytes of an InputStream of a given File. <br>
     * This method behaves exactly as calling <code>hash((new FileInputStream(file)).readAllBytes());</code>.
     * @param file The file to use
     *
     * @return The hashed Hex-Value
     *
     * @throws IOException When an Exception occurs while creating the InputStream / while reading the bytes from the stream
     */
    public String hash(final @NotNull File file) throws IOException {
        return hash(new FileInputStream(file));
    }

    public static HashAlgorithm getInstance(@NotNull String algorithm) {
        return switch (algorithm.toLowerCase(Locale.ROOT)) {
            case "sha_256", "sha-256" -> SHA_256.getInstance();
            case "sha_224", "sha-224" -> SHA_224.getInstance();
            case "sha_1", "sha-1" -> SHA_1.getInstance();
            default -> throw new IllegalArgumentException(String.format("Algorithm %s not found!", algorithm));
        };
    }
}