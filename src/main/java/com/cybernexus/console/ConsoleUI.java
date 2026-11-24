package com.cybernexus.console;

import com.cybernexus.model.User;
import com.cybernexus.service.AuthService;
import com.cybernexus.service.ScanService;
import com.cybernexus.util.InputValidator;

import java.sql.SQLException;
import java.util.Scanner;

/** Welcome screen: Register, Login, Exit. */
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

    public void start() {
        System.out.println("Welcome to CyberNexus AI");
        boolean running = true;
        while (running) {
            System.out.println();
            System.out.println("1. Register");
            System.out.println("2. Login");
            System.out.println("3. Exit");
            System.out.print("Choose: ");
            try {
                int choice = InputValidator.requireMenuChoice(scanner.nextLine(), 1, 3);
                switch (choice) {
                    case 1 -> register();
                    case 2 -> login();
                    case 3 -> running = false;
                    default -> System.out.println("Unknown option.");
                }
            } catch (IllegalArgumentException exception) {
                System.out.println("Input error: " + exception.getMessage());
            } catch (SQLException exception) {
                System.out.println("Database error: " + exception.getMessage());
            }
        }
        System.out.println("Goodbye.");
    }

    private void register() throws SQLException {
        System.out.print("Name: ");
        String name = scanner.nextLine();
        System.out.print("Email: ");
        String email = scanner.nextLine();
        System.out.print("Password (min 8 characters): ");
        String password = scanner.nextLine();
        User created = authService.register(name, email, password);
        System.out.println("Registered. You can now log in as " + created.getEmail());
    }

    private void login() throws SQLException {
        System.out.print("Email: ");
        String email = scanner.nextLine();
        System.out.print("Password: ");
        String password = scanner.nextLine();
        User user = authService.login(email, password);
        if (user == null) {
            System.out.println("Login failed. Check email and password.");
            return;
        }
        System.out.println("Login successful. Hello, " + user.getName() + ".");
        if (user.isAdmin()) {
            new AdminMenu(scanner).show(user);
        } else {
            new Dashboard(scanner, scanService).show(user);
        }
    }
}
