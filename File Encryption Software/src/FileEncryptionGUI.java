import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

public class FileEncryptionGUI {

    private static final int DEFAULT_WINDOW_WIDTH = 350;
    private static final int DEFAULT_WINDOW_HEIGHT = 400;
    private static final String PLAINTEXT_PASSWORD_FILE = "plaintextPasswords.CSV";

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> createAndShowGUI(null, null, null));
    }

    public static void createAndShowGUI(ActionListener encryptButtonListener, ActionListener decryptButtonListener, ActionListener showPasswordsButtonListener) {
        JFrame window = new JFrame("Simple File Encryption Tool");
        window.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        JLabel titleLabel = new JLabel("EasyEncrypt", SwingConstants.CENTER);
        titleLabel.setFont(new Font("Arial", Font.BOLD, 24));
        titleLabel.setOpaque(true);
        titleLabel.setBackground(new Color(255, 165, 0));
        titleLabel.setForeground(Color.WHITE);
        
        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        mainPanel.setBackground(new Color(173, 216, 230));//page

        JButton encryptButton = customizeButton("Encrypt File", encryptButtonListener, new Color(255, 165, 0));
        JButton decryptButton = customizeButton("Decrypt File", decryptButtonListener, new Color(255, 165, 0));
        JButton showPasswordsButton = customizeButton("Show Used Passwords", showPasswordsButtonListener, new Color(255, 165, 0));

        int verticalGap = 100;
        int buttonSpacing = 25;
        int leftGap = 100;

        mainPanel.add(Box.createRigidArea(new Dimension(0, verticalGap)));
        mainPanel.add(Box.createHorizontalStrut(leftGap));

        mainPanel.add(encryptButton);
        mainPanel.add(Box.createRigidArea(new Dimension(0, buttonSpacing)));
        mainPanel.add(decryptButton);
        mainPanel.add(Box.createRigidArea(new Dimension(0, buttonSpacing)));
        mainPanel.add(showPasswordsButton);

        mainPanel.add(Box.createRigidArea(new Dimension(0, verticalGap)));

        window.getContentPane().add(BorderLayout.NORTH, titleLabel);
        window.getContentPane().add(BorderLayout.CENTER, mainPanel);
        window.setSize(DEFAULT_WINDOW_WIDTH, DEFAULT_WINDOW_HEIGHT);
        window.setVisible(true);
    }

    private static JButton customizeButton(String buttonText, ActionListener listener, Color bgColor) {
        JButton button = new JButton(buttonText);
        button.addActionListener(listener);
        button.setFocusPainted(false);
        button.setBackground(bgColor);
        button.setForeground(Color.WHITE);
        button.setFont(new Font("Arial", Font.BOLD, 16));
        button.setBorder(BorderFactory.createCompoundBorder(
        BorderFactory.createLineBorder(new Color(255, 140, 0), 2), //border
        BorderFactory.createEmptyBorder(10, 15, 10, 15) //padding
        ));
        return button;
    }

    public static void displayPasswordsInfo() {
        try (BufferedReader reader = new BufferedReader(new FileReader(PLAINTEXT_PASSWORD_FILE))) {
            StringBuilder passwordsInfo = new StringBuilder("Used Passwords:\n\n");
            String line;
            while ((line = reader.readLine()) != null) {
                passwordsInfo.append(line).append("\n");
            }
            JOptionPane.showMessageDialog(null, passwordsInfo.toString(), "Used Passwords", JOptionPane.INFORMATION_MESSAGE);
        } catch (IOException e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(null, "Error reading passwords information.", "Error", JOptionPane.ERROR_MESSAGE);
        }
    }
}
