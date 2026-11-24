package com.cybernexus;

import com.cybernexus.console.ConsoleUI;
import com.cybernexus.service.AuthService;
import com.cybernexus.service.ScanService;

import java.util.Scanner;

/**
 * Main application entry point for CyberNexus AI.
 *
 * Responsibilities:
 * 1. Print the CyberNexus AI startup banner.
 * 2. Instantiate and wire shared application dependencies (Scanner, AuthService, ScanService).
 * 3. Hand over control to ConsoleUI.
 * 4. Intercept uncaught exceptions with a global safety net so the terminal never crashes abruptly.
 * 5. Guarantee clean resource release (closing Scanner) inside a finally block upon exit.
 */
public class Main {

    public static void main(String[] args) {
        printBanner();

        // Single shared scanner connected to standard input (System.in)
        Scanner scanner = new Scanner(System.in);

        try {
            // Initialize business service layer
            AuthService authService = new AuthService();
            ScanService scanService = new ScanService();

            // Inject dependencies into the Console presentation layer
            ConsoleUI consoleUI = new ConsoleUI(scanner, authService, scanService);

            // Hand off execution to the interactive terminal menu
            consoleUI.start();

        } catch (Throwable fatalError) {
            System.err.println("\n[FATAL ERROR] An unexpected system error occurred:");
            System.err.println("  " + fatalError.getMessage());
            System.err.println("Please contact your administrator or verify your database connection.");
        } finally {
            // Guarantee resource cleanup upon terminal exit
            scanner.close();
            System.out.println("[SYSTEM] Resources released. CyberNexus AI terminated safely.");
        }
    }

    /**
     * Displays a clean, professional cybersecurity startup banner.
     */
    private static void printBanner() {
        System.out.println("================================================================================");
        System.out.println("      CYBERNEXUS AI  |  INTELLIGENT CYBERSECURITY THREAT DEFENSE ENGINE       ");
        System.out.println("                       Evaluation 1 - Terminal Edition                         ");
        System.out.println("================================================================================");
    }
}
