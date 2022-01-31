import com.github.jakobwilms.cryptojar.HashAlgorithm;

import java.nio.charset.StandardCharsets;

public class Test {
    public static void main(String[] args) {
        HashAlgorithm a = HashAlgorithm.getInstance("SHA-512");
        HashAlgorithm b = HashAlgorithm.getInstance("SHA-256");
        HashAlgorithm c = HashAlgorithm.getInstance("SHA-512/t");
        System.out.println(a.hash("43534".getBytes(StandardCharsets.UTF_8)));
        System.out.println(b.hash("akldfjawkle".getBytes(StandardCharsets.UTF_8)));
        System.out.println(c.hash("df".getBytes(StandardCharsets.UTF_8), 256));

    }
}
