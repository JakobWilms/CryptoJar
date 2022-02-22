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
        System.out.println(HashAlgorithm.getInstance("sha-256").hash("abc").hashedHex());
        System.out.println(bytesToHex(MessageDigest.getInstance("SHA-256").digest("abc".getBytes(StandardCharsets.UTF_8))));

        System.out.println(-11 % 5);
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
