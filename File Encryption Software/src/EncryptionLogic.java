import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import javax.swing.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.KeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Arrays;

public class EncryptionLogic {

    consoleLog("test");

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION_AES_GCM = "AES/GCM/NoPadding";
    private static final SecureRandom secureRandom = new SecureRandom();

    private static final String PLAINTEXT_PASSWORD_FILE = "plaintextPasswords.CSV";
    private static final String ENCRYPTED_PLAINTEXT_PASSWORD_FILE = "encryptedPlaintextPasswords.enc";
    private static final String ENCRYPTED_PASSWORD_MAP_FILE = "encryptedPasswordMap.enc";
    private static final String ENCRYPTION_KEY = "enc/dec";

    private static final byte[] SALT = new byte[16];
    private static Map<String, Map<String, byte[]>> passwordMap = new HashMap<>();

    private static JFrame frame;

    static {
        secureRandom.nextBytes(SALT);
        loadAndDecryptPasswordMap();
        loadAndDecryptPlaintextPasswords();
    }

    public static void main(String[] args) {
        loadAndDecryptPasswordMap();

        // GUI setup
        SwingUtilities.invokeLater(() -> {
            ActionListener encryptListener = new FileOperationButtonListener(frame, "Encrypt");
            ActionListener decryptListener = new FileOperationButtonListener(frame, "Decrypt");
            ActionListener showPasswordsListener = e -> FileEncryptionGUI.displayPasswordsInfo();
            FileEncryptionGUI.createAndShowGUI(encryptListener, decryptListener, showPasswordsListener);
        });

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            saveAndEncryptPasswordMap();
            saveAndEncryptPlaintextPasswords();
        }));
    }


    static {
        secureRandom.nextBytes(SALT);
        loadAndDecryptPasswordMap();
        loadAndDecryptPlaintextPasswords();
    }


    @SuppressWarnings("unchecked")
    private static void loadAndDecryptPasswordMap() {
        try (ObjectInputStream ois = new ObjectInputStream(
                new CipherInputStream(new FileInputStream(ENCRYPTED_PASSWORD_MAP_FILE), getCipher(Cipher.DECRYPT_MODE)))) {
            passwordMap = (Map<String, Map<String, byte[]>>) ois.readObject();
        } catch (FileNotFoundException e) {
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @SuppressWarnings("unchecked")
    private static void loadAndDecryptPlaintextPasswords() {
        try (ObjectInputStream ois = new ObjectInputStream(
                new CipherInputStream(new FileInputStream(ENCRYPTED_PLAINTEXT_PASSWORD_FILE), getCipher(Cipher.DECRYPT_MODE)))) {
            passwordMap = (Map<String, Map<String, byte[]>>) ois.readObject();
        } catch (FileNotFoundException e) {
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static Cipher getCipher(int cipherMode) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(cipherMode, getSecretKey());
        return cipher;
    }

    private static SecretKeySpec getSecretKey() {
        byte[] keyBytes = Arrays.copyOf(ENCRYPTION_KEY.getBytes(), 16);
        return new SecretKeySpec(keyBytes, "AES");
    }

    
    private static void saveAndEncryptPasswordMap() {
        try (ObjectOutputStream oos = new ObjectOutputStream(
                new CipherOutputStream(new FileOutputStream(ENCRYPTED_PASSWORD_MAP_FILE), getCipher(Cipher.ENCRYPT_MODE)))) {
            oos.writeObject(passwordMap);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void saveAndEncryptPlaintextPasswords() {
        try (ObjectOutputStream oos = new ObjectOutputStream(
                new CipherOutputStream(new FileOutputStream(ENCRYPTED_PLAINTEXT_PASSWORD_FILE), getCipher(Cipher.ENCRYPT_MODE)))) {
            oos.writeObject(passwordMap);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    // Password CSV Handling
    private static void savePasswordInCSV(String filePath, String password) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(PLAINTEXT_PASSWORD_FILE, true))) {
            writer.println(filePath + "," + password);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // ActionListener
    private static class FileOperationButtonListener implements ActionListener {
        private JFrame parentFrame;
        private String operation;

        public FileOperationButtonListener(JFrame parentFrame, String operation) {
            this.parentFrame = parentFrame;
            this.operation = operation;
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            JFileChooser fileChooser = new JFileChooser();
            int returnValue = fileChooser.showOpenDialog(parentFrame);

            if (returnValue == JFileChooser.APPROVE_OPTION) {
                File selectedFile = fileChooser.getSelectedFile();
                String filePath = selectedFile.getAbsolutePath();

                String password = JOptionPane.showInputDialog(parentFrame, "Enter Password:");

                if (password != null && !password.isEmpty()) {
                    try {
                        if (operation.equals("Encrypt")) {
                            byte[] salt = generateSalt();
                            byte[] iv = generateIV();
                            passwordMap.put(filePath, createPasswordEntry(password, salt, iv));
                            savePasswordInCSV(filePath, password);
                            hybridEncryptFile(filePath, password, salt, iv);
                            JOptionPane.showMessageDialog(parentFrame, "File encrypted successfully!");
                        } else if (operation.equals("Decrypt")) {
                            Map<String, byte[]> passwordEntry = passwordMap.get(filePath);
                            if (passwordEntry != null) {
                                byte[] salt = passwordEntry.get("salt");
                                byte[] iv = passwordEntry.get("iv");
                                hybridDecryptFile(filePath, password, salt, iv);
                            } else {
                                JOptionPane.showMessageDialog(parentFrame, "Password not found for the file!");
                            }

                        } else if (operation.equals("ShowPasswords")) {
                            FileEncryptionGUI.displayPasswordsInfo();
                        }
                    } catch (IOException ex) {
                        ex.printStackTrace();
                        JOptionPane.showMessageDialog(parentFrame, "Error processing file.");
                    }
                } else {
                    JOptionPane.showMessageDialog(parentFrame, "Invalid password!");
                }
            }
        }
    }




    // Encryption and Decryption Methods


    private static SecretKey generateSecretKey(String password, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        Key tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), ALGORITHM);
    }


    private static byte[] generateSalt() {
        byte[] salt = new byte[16];
        secureRandom.nextBytes(salt);
        return salt;
    }

    private static byte[] generateIV() {
        byte[] iv = new byte[12];
        secureRandom.nextBytes(iv);
        return iv;
    }

    private static byte[] encryptContentGCM(byte[] content, String password, byte[] salt, byte[] iv) {
        try {
            SecretKey secretKey = generateSecretKey(password, salt);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION_AES_GCM);
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
            return cipher.doFinal(content);
        } catch (Exception e) {
            e.printStackTrace();
            return new byte[0];
        }
    }

    private static byte[] decryptContentGCM(byte[] content, String password, byte[] salt, byte[] iv) {
        try {
            SecretKey secretKey = generateSecretKey(password, salt);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION_AES_GCM);
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);
            return cipher.doFinal(content);
        } catch (Exception e) {
            e.printStackTrace();
            return new byte[0];
        }
    }




    private static void hybridEncryptFile(String filePath, String password, byte[] salt, byte[] iv) throws IOException {
        try (FileInputStream inputStream = new FileInputStream(filePath)) {
            byte[] fileBytes = new byte[(int) new File(filePath).length()];

            long startTime = System.currentTimeMillis(); //start time

            inputStream.read(fileBytes);

            byte[] encryptedBytes = encryptContentGCM(fileBytes, password, salt, iv);

            try (FileOutputStream outputStream = new FileOutputStream(filePath)) {
                outputStream.write(encryptedBytes);
            }

            long endTime = System.currentTimeMillis(); //end time

            double fileSizeMB = new File(filePath).length() / (1024.0 * 1024.0);
            long elapsedTime = endTime - startTime;
            System.out.println("Encryption took " + elapsedTime + " milliseconds. File size: " + String.format("%.2f", fileSizeMB) + " MB");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }



    
    private static void hybridDecryptFile(String filePath, String password, byte[] salt, byte[] iv) throws IOException {
        long startTime = System.currentTimeMillis(); // start time
    
        try (FileInputStream inputStream = new FileInputStream(filePath)) {
            byte[] fileBytes = new byte[(int) new File(filePath).length()];
            inputStream.read(fileBytes);
    
            byte[] decryptedBytes = decryptContentGCM(fileBytes, password, salt, iv);
    
            if (decryptedBytes.length > 0) {
                try (FileOutputStream outputStream = new FileOutputStream(filePath)) {
                    outputStream.write(decryptedBytes);
                }
    
                long endTime = System.currentTimeMillis(); // end time
                double fileSizeMB = new File(filePath).length() / (1024.0 * 1024.0);
                long elapsedTime = endTime - startTime;
                System.out.println("Decryption took " + elapsedTime + " milliseconds. File size: " + String.format("%.2f", fileSizeMB) + " MB");
    
                // Display success message
                JOptionPane.showMessageDialog(null, "File decrypted successfully!");
            } else {
                // Decryption failed messag 
                JOptionPane.showMessageDialog(null, "Invalid password! Decryption failed.");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    

    





    private static Map<String, byte[]> createPasswordEntry(String password, byte[] salt, byte[] iv) {
        Map<String, byte[]> entry = new HashMap<>();
        entry.put("password", (password != null) ? password.getBytes() : null);
        entry.put("salt", salt);
        entry.put("iv", iv);
        return entry;
    }
}
