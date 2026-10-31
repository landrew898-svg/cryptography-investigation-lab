import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.MGF1ParameterSpec;

/** Generate a tiny disposable dataset; never uses the original lab keys. */
public class DemoFixture {
    private static final OAEPParameterSpec OAEP = new OAEPParameterSpec(
        "SHA-1", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);

    private static byte[] rsa(int mode, java.security.Key key, byte[] bytes) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        cipher.init(mode, key, OAEP);
        return cipher.doFinal(bytes);
    }

    private static byte[] aes(int mode, byte[] key, byte[] bytes) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(mode, new SecretKeySpec(key, "AES"), new IvParameterSpec(new byte[16]));
        return cipher.doFinal(bytes);
    }

    private static void pem(Path path, String type, byte[] bytes) throws Exception {
        String encoded = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(bytes);
        Files.writeString(path, "-----BEGIN " + type + "-----\n" + encoded
            + "\n-----END " + type + "-----\n", StandardCharsets.US_ASCII);
    }

    private static String md5(byte[] bytes) throws Exception {
        StringBuilder result = new StringBuilder();
        for (byte b : MessageDigest.getInstance("MD5").digest(bytes)) {
            result.append(String.format("%02x", b & 255));
        }
        return result.toString();
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("Usage: java DemoFixture <new-directory>");
        Path root = Path.of(args[0]);
        // Refuse an existing directory to avoid replacing previous results.
        Files.createDirectory(root);
        for (String folder : new String[]{"plain/nested", "rsa", "aes", "messages", "hashes", "expected"}) {
            Files.createDirectories(root.resolve(folder));
        }
        byte[] plain = "Cryptography lab demo.\n".getBytes(StandardCharsets.UTF_8);
        byte[] padded = Arrays.copyOf(plain, 32);
        Arrays.fill(padded, plain.length, padded.length, (byte)'!');
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair correct = generator.generateKeyPair();
        KeyPair decoy = generator.generateKeyPair();
        byte[] encryptedKey = rsa(Cipher.ENCRYPT_MODE, correct.getPublic(), key);
        byte[] encryptedMessage = aes(Cipher.ENCRYPT_MODE, key, padded);
        // Independently exercise JCA decryption before writing the demo.
        if (!Arrays.equals(key, rsa(Cipher.DECRYPT_MODE, correct.getPrivate(), encryptedKey))
                || !Arrays.equals(padded, aes(Cipher.DECRYPT_MODE, key, encryptedMessage))) {
            throw new IllegalStateException("Demo cryptographic round trip failed");
        }
        pem(root.resolve("rsa/01-decoy.pem"), "PRIVATE KEY", decoy.getPrivate().getEncoded());
        pem(root.resolve("rsa/02-match.pem"), "PRIVATE KEY", correct.getPrivate().getEncoded());
        pem(root.resolve("public.pem"), "PUBLIC KEY", correct.getPublic().getEncoded());
        Files.write(root.resolve("plain/decoy.txt"), new byte[]{'n', 'o'});
        Files.write(root.resolve("plain/nested/match.txt"), plain);
        Files.write(root.resolve("aes/01-invalid.eaes"), new byte[]{1, 2, 3});
        Files.write(root.resolve("aes/02-match.eaes"), encryptedKey);
        Files.write(root.resolve("messages/01-invalid.emsg"), new byte[]{1, 2, 3});
        Files.write(root.resolve("messages/02-match.emsg"), encryptedMessage);
        Files.write(root.resolve("expected/session.key"), key);
        Files.write(root.resolve("expected/message.bin"), padded);
        Files.writeString(root.resolve("hashes/plain.md5"), md5(plain) + "\n");
        Files.writeString(root.resolve("hashes/aes.md5"), md5(key) + "\n");
        Files.writeString(root.resolve("hashes/message.md5"), md5(padded) + "\n");
        System.out.println("Generated demo at " + root + "; RSA and AES round trips passed.");
    }
}
