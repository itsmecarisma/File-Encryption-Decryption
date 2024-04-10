import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;

public class FileEncryptionDecryption {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES";

    public static void main(String[] args) {
        String keyFile = "secret.key";
        String inputFile = "example.txt";
        String encryptedFile = "example.txt.encrypted";
        String decryptedFile = "example_decrypted.txt";

        try {
            SecretKey secretKey = generateKey();
            saveKey(secretKey, keyFile);

            encryptFile(inputFile, encryptedFile, secretKey);
            System.out.println("File encrypted successfully: " + encryptedFile);

            decryptFile(encryptedFile, decryptedFile, loadKey(keyFile));
            System.out.println("File decrypted successfully: " + decryptedFile);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(128); // 128-bit key size
        return keyGenerator.generateKey();
    }

    public static void saveKey(SecretKey secretKey, String fileName) throws IOException {
        try (ObjectOutputStream outputStream = new ObjectOutputStream(new FileOutputStream(fileName))) {
            outputStream.writeObject(secretKey.getEncoded());
        }
    }

    public static SecretKey loadKey(String fileName) throws IOException, ClassNotFoundException {
        byte[] keyBytes = Files.readAllBytes(Paths.get(fileName));
        return new SecretKeySpec(keyBytes, ALGORITHM);
    }

    public static void encryptFile(String inputFileName, String outputFileName, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        try (FileInputStream inputStream = new FileInputStream(inputFileName);
             FileOutputStream outputStream = new FileOutputStream(outputFileName)) {
            byte[] inputBytes = new byte[(int) new File(inputFileName).length()];
            inputStream.read(inputBytes);

            byte[] outputBytes = cipher.doFinal(inputBytes);
            outputStream.write(outputBytes);
        }
    }

    public static void decryptFile(String inputFileName, String outputFileName, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        try (FileInputStream inputStream = new FileInputStream(inputFileName);
             FileOutputStream outputStream = new FileOutputStream(outputFileName)) {
            byte[] inputBytes = new byte[(int) new File(inputFileName).length()];
            inputStream.read(inputBytes);

            byte[] outputBytes = cipher.doFinal(inputBytes);
            outputStream.write(outputBytes);
        }
    }
}
