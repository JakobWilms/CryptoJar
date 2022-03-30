import com.github.jakobwilms.cryptojar.HashAlgorithm;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Test {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        /*
        Runnable runnable = () -> System.out.println(HashAlgorithm.getInstance("sha-512").hash(System.currentTimeMillis()));
        ScheduledExecutorService service = Executors.newSingleThreadScheduledExecutor();
        service.scheduleAtFixedRate(runnable, 0L, 1, TimeUnit.MILLISECONDS);
         */
        System.out.println(HashAlgorithm.getInstance("sha3-256").hash("ẞ˙Ł€&®ĦŦ’Ŋ&ÐẞªŊẞŊ’ẞẞẞẞẞẞẞẞẞẞẞẞ€Ł↑ıııııııııııııııııııııııııŁŁŁŁŁŁŁŁŁŁŁŁŁŁŁŁŁŁŁŁŁŁŁŁŁŁŁŁŁŁŁΩΩΩΩΩΩΩΩΩΩΩΩΩΩΩΩΩΩΩΩΩΩΩ‹‘’‘‘‘‘‘‘‘‘‘‘‘"));
        System.out.println(bytesToHex(MessageDigest.getInstance("SHA3-256").digest("ẞ˙Ł€&®ĦŦ’Ŋ&ÐẞªŊẞŊ’ẞẞẞẞẞẞẞẞẞẞẞẞ€Ł↑ıııııııııııııııııııııııııŁŁŁŁŁŁŁŁŁŁŁŁŁŁŁŁŁŁŁŁŁŁŁŁŁŁŁŁŁŁŁΩΩΩΩΩΩΩΩΩΩΩΩΩΩΩΩΩΩΩΩΩΩΩ‹‘’‘‘‘‘‘‘‘‘‘‘‘".getBytes(StandardCharsets.UTF_8))));

    }

    private static String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
