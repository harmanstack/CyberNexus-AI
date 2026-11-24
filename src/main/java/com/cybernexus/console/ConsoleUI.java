package com.cybernexus.console;

import com.cybernexus.model.User;
import com.cybernexus.service.AuthService;
import com.cybernexus.service.ScanService;
import com.cybernexus.util.InputValidator;

import java.sql.SQLException;
import java.util.Scanner;

/**
 * Main terminal presentation interface for CyberNexus AI.
 * Handles the top-level welcome menu, user registration, authentication,
 * and routing to either the User Dashboard or Admin Menu.
 */
public class ConsoleUI {

    private final Scanner scanner;
    private final AuthService authService;
    private final ScanService scanService;

    public ConsoleUI() {
        this(new Scanner(System.in), new AuthService(), new ScanService());
    }

    public ConsoleUI(Scanner scanner, AuthService authService, ScanService scanService) {
        this.scanner = scanner;
        this.authService = authService;
        this.scanService = scanService;
    }

    /**
     * Entry point allowing ConsoleUI to be run directly from IntelliJ.
     */
    public static void main(String[] args) {
        new ConsoleUI().start();
    }

    /**
     * Starts the interactive welcome menu loop.
     */
    public void start() {
        boolean running = true;

        while (running) {
            displayWelcomeMenu();

            try {
                System.out.print("Select an option: ");
                int choice = InputValidator.requireMenuChoice(scanner.nextLine(), 1, 3);

                switch (choice) {
                    case 1 -> handleRegistration();
                    case 2 -> handleLogin();
                    case 3 -> {
                        running = false;
                        System.out.println("\n[SYSTEM] Thank you for using CyberNexus AI. Stay secure!");
                    }
                    default -> System.out.println("[WARN] Unknown option. Please choose 1, 2, or 3.");
                }
            } catch (IllegalArgumentException exception) {
                System.out.println("[ERROR] " + exception.getMessage());
            } catch (SQLException exception) {
                System.out.println("[DATABASE ERROR] Could not complete operation: " + exception.getMessage());
            } catch (Exception exception) {
                System.out.println("[UNEXPECTED ERROR] An error occurred: " + exception.getMessage());
            }

            if (running) {
                System.out.println(); // Formatting spacer between iterations
            }
        }
    }

    /**
     * Displays the welcome screen banner and options.
     */
    private void displayWelcomeMenu() {
        System.out.println("====================================");
        System.out.println("       WELCOME TO CYBERNEXUS AI     ");
        System.out.println("====================================");
        System.out.println("1. Register");
        System.out.println("2. Login");
        System.out.println("3. Exit");
        System.out.println("------------------------------------");
    }

    /**
     * Guides the user through account registration.
     */
    private void handleRegistration() throws SQLException {
        System.out.println("\n--- USER REGISTRATION ---");

        System.out.print("Enter username (min 3 chars): ");
        String name = scanner.nextLine();

        System.out.print("Enter email address: ");
        String email = scanner.nextLine();

        System.out.print("Enter password (min 8 chars): ");
        String password = scanner.nextLine();

        try {
            User newUser = authService.register(name, email, password);
            System.out.println("\n[SUCCESS] Account registered successfully!");
            System.out.println("  User ID : " + newUser.getId());
            System.out.println("  Username: " + newUser.getName());
            System.out.println("  Email   : " + newUser.getEmail());
            System.out.println("You can now log in using option 2.");
        } catch (IllegalArgumentException ex) {
            System.out.println("\n[REGISTRATION FAILED] " + ex.getMessage());
        }
    }

    /**
     * Guides the user through authentication and opens the appropriate menu.
     */
    private void handleLogin() throws SQLException {
        System.out.println("\n--- USER LOGIN ---");

        System.out.print("Enter username or email: ");
        String identifier = scanner.nextLine();

        System.out.print("Enter password: ");
        String password = scanner.nextLine();

        User user = authService.login(identifier, password);

        if (user == null) {
            System.out.println("\n[LOGIN FAILED] Invalid username/email or password.");
            return;
        }

        System.out.println("\n[SUCCESS] Login successful! Welcome, " + user.getName() + " [" + user.getRole().toUpperCase() + "].");

        // Route based on role
        if (user.isAdmin()) {
            new AdminMenu(scanner).show(user);
        } else {
            new Dashboard(scanner, scanService).show(user);
        }
    }
}
