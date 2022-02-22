package com.github.jakobwilms.cryptojar;

import org.jetbrains.annotations.NotNull;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidParameterException;
import java.util.BitSet;
import java.util.Locale;

public abstract class HashAlgorithm {

    /**
     * Single Private Constructor to prevent the default one from being generated
     */
    protected HashAlgorithm() {}

    public static HashAlgorithm getInstance(@NotNull String algorithm) {
        return switch (algorithm.toLowerCase(Locale.ROOT)) {
            case "sha_256", "sha-256" -> SHA_256.getInstance();
            case "sha_224", "sha-224" -> SHA_224.getInstance();
            case "sha_1", "sha-1" -> SHA_1.getInstance();
            case "sha_384", "sha-384" -> SHA_384.getInstance();
            case "sha_512", "sha-512" -> SHA_512.getInstance();
            case "sha_512/t", "sha-512/t", "sha_512t", "sha-512t" -> SHA_512_T.getInstance();
            default -> throw new IllegalArgumentException(String.format("Algorithm %s not found!", algorithm));
        };
    }

    /**
     * Hash a given array of bytes.
     *
     * @param bytes The Array of bytes to hash
     *
     * @return The hashed Hex-Value
     */
    public HashReturn hash(final byte @NotNull [] bytes) {
        if (this instanceof SHA_512_T)
            throw new InvalidParameterException("Do not use SHA-512/t without a value for t!!!");
        return hash(bytes, -1);
    }

    /**
     * Hash a given array of bytes.
     *
     * @param bytes    The Array of bytes to hash
     * @param truncate Truncate the result to a given length. WILL BE IGNORED BY ALGORITHMS OTHER THAN SHA-512/t !!!
     *
     * @return The hashed Hex-Value
     */
    public abstract HashReturn hash(final byte @NotNull [] bytes, final int truncate);

    /**
     * Hash the bytes of a given InputStream. <br>
     * This method behaves exactly as calling <code>hash(stream.readAllBytes());</code>.
     *
     * @param stream The InputStream to use
     *
     * @return The hashed Hex-Value
     *
     * @throws IOException When an Exception Occurs when reading the bytes from the stream
     */
    public HashReturn hash(final @NotNull InputStream stream) throws IOException {
        return hash(stream.readAllBytes());
    }

    /**
     * Hash the bytes of a given InputStream. <br>
     * This method behaves exactly as calling <code>hash(stream.readAllBytes());</code>.
     *
     * @param stream   The InputStream to use
     * @param truncate Truncate the result to a given length. WILL BE IGNORED BY ALGORITHMS OTHER THAN SHA-512/t !!!
     *
     * @return The hashed Hex-Value
     *
     * @throws IOException When an Exception Occurs when reading the bytes from the stream
     */
    public HashReturn hash(final @NotNull InputStream stream, final int truncate) throws IOException {
        return hash(stream.readAllBytes(), truncate);
    }

    /**
     * Hash the bytes of an InputStream of a given File. <br>
     * This method behaves exactly as calling <code>hash((new FileInputStream(file)).readAllBytes());</code>.
     *
     * @param file The file to use
     *
     * @return The hashed Hex-Value
     *
     * @throws IOException When an Exception occurs while creating the InputStream / while reading the bytes from the stream
     */
    public HashReturn hash(final @NotNull File file) throws IOException {
        return hash(new FileInputStream(file));
    }

    /**
     * Hash the bytes of an InputStream of a given File. <br>
     * This method behaves exactly as calling <code>hash((new FileInputStream(file)).readAllBytes());</code>.
     *
     * @param file     The file to use
     * @param truncate Truncate the result to a given length. WILL BE IGNORED BY ALGORITHMS OTHER THAN SHA-512/t !!!
     *
     * @return The hashed Hex-Value
     *
     * @throws IOException When an Exception occurs while creating the InputStream / while reading the bytes from the stream
     */
    public HashReturn hash(final @NotNull File file, final int truncate) throws IOException {
        return hash(new FileInputStream(file), truncate);
    }

    /**
     * Preprocess a BitSet with a given size. <br>
     * This algorithm executes the following steps as specified by the Federal Information Processing Standards Publication: <br>
     * 1) Padding the Message <br>
     * 2) Parsing the Message <br>
     *
     * @param bitSet The set of bits to preprocess
     * @param size   The size of the BitSet
     *
     * @return The preprocessed BitSet, as an array of BitSets, each with a size of 512
     */
    abstract BitSet @NotNull [] preprocess(final @NotNull BitSet bitSet, int size);

    public HashReturn hash(@NotNull String hash, Charset charset) {
        return hash(hash.getBytes(charset));
    }

    public HashReturn hash(String hash) {
        return hash(hash, StandardCharsets.UTF_8);
    }

    public HashReturn hash(long hash) {
        return hash(ByteBuffer.allocate(8).putLong(hash).array());
    }

    protected byte @NotNull [] trimTo(final byte @NotNull [] bytes, int trim) {
        if (bytes.length == trim) return bytes;
        byte[] temp = new byte[trim];
        if (bytes.length > trim) System.arraycopy(bytes, bytes.length - trim, temp, 0, trim);
        else for (int i = 0; i < trim; i++) temp[i] = (trim - i) > bytes.length ? 0 : bytes[bytes.length - trim + i];

        return temp;
    }
}
