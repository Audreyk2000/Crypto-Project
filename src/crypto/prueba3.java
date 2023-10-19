package crypto;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Scanner;
import java.security.*;

public class prueba3 {
    public static void main(String[] args) throws Exception {
        // Get directory path
        String dirPath = "C:\\Users\\andre\\OneDrive\\Escritorio\\carpeta prueba";

        // Generate secret key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        SecureRandom random = new SecureRandom();
        keyGen.init(random);
        SecretKey secretKey = keyGen.generateKey();
        IvParameterSpec IV = generateIv();
        String placeHolderPass = "manzana";

        // Encrypt directory
        encryptDirectory(dirPath, secretKey, IV);

        // Save key to file
        saveKeyToFile(dirPath, secretKey);

        // Ask user for key
        Scanner scanner = new Scanner(System.in);
        int i=1;
        do {
        System.out.println("Enter the password: \n");
        String input = new String();
        input = scanner.nextLine();
        if(input.equals(placeHolderPass))
        i=0;
        else
        	System.out.println("Contraseña incorrecta");
        }while(i!=0);
        
        SecretKey userKey = getUserKey(dirPath);
     // Decrypt directory
        decryptDirectory(dirPath, userKey, IV);
       
  
        
    }

    public static void encryptDirectory(String dirPath, SecretKey secretKey,IvParameterSpec IV) throws Exception {
        // Initialize cipher
        Cipher cipher = Cipher.getInstance("AES");

        // Initialize cipher with secret key
        cipher.init(Cipher.ENCRYPT_MODE, secretKey,IV);

        // Iterate over all files in directory
        Files.walk(Paths.get(dirPath)).forEach(filePath -> {
            if (Files.isRegularFile(filePath)) {
                try {
                    // Check if file is a text file or an image file
                    String mimeType = Files.probeContentType(filePath);
                    if (mimeType != null && (mimeType.startsWith("text/") || mimeType.startsWith("image/png"))) {
                        // Read contents of file into byte array
                        byte[] fileContent = Files.readAllBytes(filePath);

                        // Encrypt data
                        byte[] encryptedContent = cipher.doFinal(fileContent);

                        // Write encrypted data back to file
                        FileOutputStream outputStream = new FileOutputStream(filePath.toFile());
                        outputStream.write(encryptedContent);
                        outputStream.close();
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
    }

    public static void saveKeyToFile(String dirPath, SecretKey secretKey) throws Exception {
        // Write secret key to file
        FileOutputStream outputStream = new FileOutputStream(dirPath + "/secret.key");
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);
        objectOutputStream.writeObject(secretKey);
        objectOutputStream.close();
    }

    public static SecretKey getUserKey(String dirPath) throws Exception {
        // Read secret key from file
        FileInputStream inputStream = new FileInputStream(dirPath + "/secret.key");
        ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);
        SecretKey secretKey = (SecretKey) objectInputStream.readObject();
        objectInputStream.close();

        return secretKey;
    }

    public static void decryptDirectory(String dirPath, SecretKey secretKey,IvParameterSpec IV) throws Exception {
        // Initialize cipher
        Cipher cipher = Cipher.getInstance("AES");

        // Initialize cipher with secret key
        cipher.init(Cipher.DECRYPT_MODE, secretKey, IV);

        // Iterate over all files in directory
        Files.walk(Paths.get(dirPath)).forEach(filePath -> {
            if (Files.isRegularFile(filePath)) {
                try {
                    // Check if file is a text file or an image file
                    String mimeType = Files.probeContentType(filePath);
                    if (mimeType != null && (mimeType.startsWith("text/") || mimeType.startsWith("image/png"))) {
                        // Read contents of file into byte array
                        byte[] fileContent = Files.readAllBytes(filePath);

                        // Decrypt data
                        byte[] decryptedContent = cipher.doFinal(fileContent);

                        // Write decrypted data back to file
                        FileOutputStream outputStream = new FileOutputStream(filePath.toFile());
                        outputStream.write(decryptedContent);
                        outputStream.close();
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
    }
    public static IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }
}