import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionListener;
import com.opencsv.CSVReader;
import com.opencsv.CSVWriter;
import com.opencsv.exceptions.CsvException;
import java.io.*;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;

public class LoginLogic {
    private static final String USERS_CSV_PATH = "users.csv";
    private static JTextField usernameField;
    private static JPasswordField passwordField;
    private static List<User> users = new ArrayList<>();

    static {
        loadUsersFromCSV();
    }


    public static JTextField getUsernameField() {
        return usernameField;
    }

    public static JPasswordField getPasswordField() {
        return passwordField;
    }

    private static JButton createLoginButton(JFrame loginFrame) {
        JButton loginButton = customizeButton("Login", e -> handleLogin(loginFrame), new Color(255, 165, 0));
        return loginButton;
    }


    private static JButton createSignupButton(JFrame loginFrame) {
        JButton signupButton = customizeButton("Signup", e -> handleSignup(loginFrame), new Color(50, 205, 50));
        return signupButton;
    }


    private static void handleLogin(JFrame loginFrame) {
        String username = usernameField.getText();
        char[] password = passwordField.getPassword();
        if (isValidLogin(username, password)) {
            loginFrame.dispose();
            Runnable encryptionLogicRunnable = () -> EncryptionLogic.main(null);
            SwingUtilities.invokeLater(encryptionLogicRunnable);
        } else {
            JOptionPane.showMessageDialog(loginFrame, "Invalid username or password", "Login Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    

    private static void handleSignup(JFrame loginFrame) {
        String username = usernameField.getText();
        char[] password = passwordField.getPassword();
        if (username.isEmpty() || password.length == 0) {
            JOptionPane.showMessageDialog(loginFrame, "Please enter a valid username and password", "Signup Error", JOptionPane.ERROR_MESSAGE);
        } else {
            users.add(new User(username, new String(password)));
            saveUsersToCSV();
            JOptionPane.showMessageDialog(loginFrame, "Signup successful! You can now log in.", "Signup Success", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private static boolean isValidLogin(String username, char[] password) {
        return users.stream().anyMatch(user -> user.getUsername().equals(username) && Arrays.equals(password, user.getPassword()));
    }

    private static class User {
        private final String username;
        private final String password;

        public User(String username, String password) {
            this.username = username;
            this.password = password;
        }

        public String getUsername() {
            return username;
        }

        public char[] getPassword() {
            return password.toCharArray();
        }
    }


    private static void loadUsersFromCSV() {
        File file = new File(USERS_CSV_PATH);
        if (!file.exists()) {
            try {
                file.createNewFile();
            } catch (IOException e) {
                e.printStackTrace();
            }
            return; // If file doesn't exist, just return
        }
    
        try (CSVReader reader = new CSVReader(new FileReader(file))) {
            List<String[]> data = reader.readAll();
            for (String[] line : data) {
                if (line.length >= 2) { // Check if line has at least 2 elements
                    users.add(new User(line[0], line[1]));
                } else {
                    // Handle the case where the line doesn't have enough elements
                    System.err.println("Invalid line in CSV: " + Arrays.toString(line));
                }
            }
        } catch (IOException | CsvException e) {
            e.printStackTrace();
        }
    }
        
    

    //save users to csv
    private static void saveUsersToCSV() {
        try (CSVWriter writer = new CSVWriter(new FileWriter(USERS_CSV_PATH))) {
            for (User user : users) {
                writer.writeNext(new String[]{user.getUsername(), new String(user.getPassword())});
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static JFrame createLoginFrame() {
    JFrame loginFrame = new JFrame("Login");
    loginFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

    JPanel loginPanel = new JPanel(new GridLayout(0, 1, 10, 10));
    loginPanel.setBackground(new Color(173, 216, 230));

    usernameField = new JTextField(3);
    passwordField = new JPasswordField(3);
    JButton loginButton = createLoginButton(loginFrame);
    JButton signupButton = createSignupButton(loginFrame);

    loginPanel.add(new JLabel("Username:"));
    loginPanel.add(usernameField);
    loginPanel.add(new JLabel("Password:"));
    loginPanel.add(passwordField);
    loginPanel.add(loginButton);
    loginPanel.add(signupButton);

    loginFrame.getContentPane().add(BorderLayout.CENTER, loginPanel);
    loginFrame.setSize(350, 400);

    return loginFrame;
}

private static JButton customizeButton(String buttonText, ActionListener listener, Color bgColor) {
    JButton button = new JButton(buttonText);
    button.addActionListener(listener);
    button.setFocusPainted(false);
    button.setBackground(bgColor);
    button.setForeground(Color.WHITE);
    button.setFont(new Font("Arial", Font.BOLD, 16));
    button.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(255, 140, 0), 2),
            BorderFactory.createEmptyBorder(10, 15, 10, 15)
    ));
    return button;
}

public static void createAndShowLogin() {
    JFrame loginFrame = createLoginFrame();
    loginFrame.setVisible(true);
    }

    
    //Start app on this file
    public static void main(String[] args) {
        SwingUtilities.invokeLater(LoginLogic::createAndShowLogin);
    }

}
