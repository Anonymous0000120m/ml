import java.io.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class SSHKeyManager {

    public static void main(String[] args) {
        if (args.length != 3) {
            System.out.println("Usage: java SSHKeyManager <publicKeyFilePath> <privateKeyFilePath> <logFilePath>");
            return;
        }

        String publicKeyFilePath = args[0];
        String privateKeyFilePath = args[1];
        String logFilePath = args[2];

        try {
            // Generate key pair
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // Save public key
            saveKey(publicKeyFilePath, keyPair.getPublic());

            // Save private key
            saveEncryptedPrivateKey(privateKeyFilePath, keyPair.getPrivate(), "your_password_here");

            // Log actions
            logAction(logFilePath, "SSH key pair generated and saved successfully.");
        } catch (NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
            logAction(logFilePath, "Error generating or saving SSH key pair: " + e.getMessage());
        }
    }

    private static void saveKey(String filePath, Key key) throws IOException {
        byte[] keyBytes = key.getEncoded();
        FileOutputStream fos = new FileOutputStream(filePath);
        fos.write(keyBytes);
        fos.close();
    }

    private static void saveEncryptedPrivateKey(String filePath, PrivateKey privateKey, String password) throws IOException {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, generateAESKey(password));
            byte[] encryptedPrivateKeyBytes = cipher.doFinal(privateKey.getEncoded());
            FileOutputStream fos = new FileOutputStream(filePath);
            fos.write(encryptedPrivateKeyBytes);
            fos.close();
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            throw new IOException("Error encrypting private key: " + e.getMessage());
        }
    }

    private static SecretKey generateAESKey(String password) throws NoSuchAlgorithmException {
        byte[] passwordBytes = password.getBytes();
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(passwordBytes);
        byte[] keyBytes = md.digest();
        return new SecretKeySpec(keyBytes, "AES");
    }

    private static void logAction(String logFilePath, String message) throws IOException {
        FileWriter writer = new FileWriter(logFilePath, true);
        writer.write(message + "\n");
        writer.close();
    }
}
