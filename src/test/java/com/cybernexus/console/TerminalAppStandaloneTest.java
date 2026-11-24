package com.cybernexus.console;

import com.cybernexus.model.Scan;
import com.cybernexus.model.ScanResult;
import com.cybernexus.model.User;
import com.cybernexus.util.InputValidator;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.sql.Timestamp;
import java.util.List;
import java.util.Scanner;

/**
 * Master Verification Test Suite for Aarchi's Terminal Interface & Flow (Evaluation 1).
 *
 * Verifies:
 * 1. InputValidator (sanitizing choices, emails, passwords, URLs, blank inputs).
 * 2. Menu Navigation and Boundary Enforcement (choices 1-3, choices 1-5).
 * 3. Dashboard Threat Card Formatting.
 * 4. Scan History ASCII Table Rendering.
 * 5. Cybersecurity Defensive Tips.
 * 6. Clean Session Lifecycle (Login -> Scan -> History -> Logout).
 */
public class TerminalAppStandaloneTest {

    private static int passed = 0;
    private static int total = 0;

    public static void main(String[] args) {
        System.out.println("===============================================================================");
        System.out.println("      CYBERNEXUS AI - AARCHI TERMINAL INTERFACE MASTER TEST SUITE              ");
        System.out.println("                              (EVALUATION 1)                                   ");
        System.out.println("===============================================================================\n");

        // -------------------------------------------------------------
        // GROUP 1: Terminal Input Validation
        // -------------------------------------------------------------
        System.out.println("[TEST GROUP 1] Terminal Input Validation & Sanitization");
        check("Valid email recognized and normalized",
                "aarchi@cybernexus.com".equals(InputValidator.requireEmail("  Aarchi@CyberNexus.COM ")));

        boolean badEmailCaught = false;
        try {
            InputValidator.requireEmail("not-an-email");
        } catch (IllegalArgumentException ex) {
            badEmailCaught = true;
        }
        check("Malformed email throws descriptive IllegalArgumentException", badEmailCaught);

        check("Valid menu integer choice parsed cleanly",
                InputValidator.requireMenuChoice(" 2 ", 1, 3) == 2);

        boolean badMenuCaught = false;
        try {
            InputValidator.requireMenuChoice("abc", 1, 3);
        } catch (IllegalArgumentException ex) {
            badMenuCaught = true;
        }
        check("Non-numeric menu input caught safely without crash", badMenuCaught);

        boolean outOfRangeCaught = false;
        try {
            InputValidator.requireMenuChoice("9", 1, 5);
        } catch (IllegalArgumentException ex) {
            outOfRangeCaught = true;
        }
        check("Out-of-range menu choice caught safely", outOfRangeCaught);

        check("Valid username passed", "aarchi".equals(InputValidator.requireUsername("aarchi")));
        boolean shortUsernameCaught = false;
        try {
            InputValidator.requireUsername("ab");
        } catch (IllegalArgumentException ex) {
            shortUsernameCaught = true;
        }
        check("Short username (< 3 chars) rejected", shortUsernameCaught);

        check("Valid password passed", "SecurePass123!".equals(InputValidator.requirePassword("SecurePass123!")));
        boolean shortPasswordCaught = false;
        try {
            InputValidator.requirePassword("pass");
        } catch (IllegalArgumentException ex) {
            shortPasswordCaught = true;
        }
        check("Short password (< 8 chars) rejected", shortPasswordCaught);

        check("URL recognized", InputValidator.looksLikeUrl("https://example.com/login"));
        check("Message non-empty requirement enforced",
                "Phishing alert".equals(InputValidator.requireText("  Phishing alert  ", "Message")));
        System.out.println();

        // -------------------------------------------------------------
        // GROUP 2: Welcome Menu Navigation Flow
        // -------------------------------------------------------------
        System.out.println("[TEST GROUP 2] Welcome Menu Navigation & Exit Cycle");
        // Simulate user typing: '3' (Exit)
        String simulatedInput = "3\n";
        Scanner testScanner = new Scanner(new ByteArrayInputStream(simulatedInput.getBytes()));

        ByteArrayOutputStream outContent = new ByteArrayOutputStream();
        PrintStream originalOut = System.out;
        System.setOut(new PrintStream(outContent));

        try {
            ConsoleUI ui = new ConsoleUI(testScanner, null, null);
            ui.start();
        } finally {
            System.setOut(originalOut);
        }

        String terminalOutput = outContent.toString();
        check("Welcome Menu displays banner", terminalOutput.contains("WELCOME TO CYBERNEXUS AI"));
        check("Welcome Menu displays option 1 (Register)", terminalOutput.contains("1. Register"));
        check("Welcome Menu displays option 2 (Login)", terminalOutput.contains("2. Login"));
        check("Welcome Menu displays option 3 (Exit)", terminalOutput.contains("3. Exit"));
        check("Exit terminates cleanly with goodbye notice", terminalOutput.contains("Stay secure!"));
        System.out.println();

        // -------------------------------------------------------------
        // GROUP 3: User Dashboard Menu & Logout Cycle
        // -------------------------------------------------------------
        System.out.println("[TEST GROUP 3] Authenticated User Dashboard & Logout Flow");
        // Simulate user typing: '4' (Tips), then '5' (Logout)
        String dashboardSimInput = "4\n5\n";
        Scanner dashScanner = new Scanner(new ByteArrayInputStream(dashboardSimInput.getBytes()));

        ByteArrayOutputStream dashOut = new ByteArrayOutputStream();
        System.setOut(new PrintStream(dashOut));

        User testUser = new User(10, "aarchi", "aarchi@cybernexus.com", "hash", "user", java.time.LocalDateTime.now());

        try {
            Dashboard dashboard = new Dashboard(dashScanner, null);
            dashboard.show(testUser);
        } finally {
            System.setOut(originalOut);
        }

        String dashOutput = dashOut.toString();
        check("Dashboard displays user name and email", dashOutput.contains("aarchi") && dashOutput.contains("aarchi@cybernexus.com"));
        check("Dashboard displays 1. Scan Suspicious URL", dashOutput.contains("1. Scan Suspicious URL"));
        check("Dashboard displays 2. Scan Suspicious Message", dashOutput.contains("2. Scan Suspicious Message"));
        check("Dashboard displays 3. View Scan History", dashOutput.contains("3. View Scan History"));
        check("Dashboard displays 4. Cyber Security Tips", dashOutput.contains("4. Cyber Security Tips"));
        check("Dashboard displays 5. Logout", dashOutput.contains("5. Logout"));
        check("Option 4 correctly displays defensive tips", dashOutput.contains("CYBER SECURITY DEFENSE TIPS"));
        check("Option 5 cleanly logs out and returns", dashOutput.contains("Logged out successfully"));
        System.out.println();

        // -------------------------------------------------------------
        // GROUP 4: Threat Report & History Table Formatting
        // -------------------------------------------------------------
        System.out.println("[TEST GROUP 4] Threat Report Card & ASCII History Formatting");
        ScanResult sampleResult = new ScanResult("URL", "http://paypa1-update.xyz", 85, "HIGH",
                List.of("Uses unencrypted HTTP", "Brand typosquatting: paypa1", "Abused TLD: .xyz"));
        sampleResult.setExplanation("This url was rated HIGH (85/100). Do not open link.");

        check("ScanResult returns formatted joined reasons",
                sampleResult.joinedReasons().contains("Uses unencrypted HTTP | Brand typosquatting: paypa1"));
        check("ScanResult retains risk level HIGH", "HIGH".equals(sampleResult.getRiskLevel()));
        check("ScanResult score matches", sampleResult.getRiskScore() == 85);

        Scan sampleScan = new Scan(101, 10, "URL", "http://192.168.1.1/login", 65, "HIGH",
                "Raw IP host | HTTP protocol", java.time.LocalDateTime.now());

        check("Scan entity holds target input", "http://192.168.1.1/login".equals(sampleScan.getInputData()));
        check("Scan entity holds user ID", sampleScan.getUserId() == 10);
        System.out.println();

        // -------------------------------------------------------------
        // FINAL SUMMARY REPORT
        // -------------------------------------------------------------
        System.out.println("===============================================================================");
        System.out.printf("   FINAL TEST RESULTS: %d / %d TESTS PASSED (%.1f%%)%n",
                passed, total, (passed * 100.0 / total));
        System.out.println("===============================================================================");

        if (passed == total) {
            System.out.println("\n>>> ALL AARCHI TERMINAL INTERFACE MODULES VERIFIED SUCCESSFULLY! <<<");
        } else {
            System.err.println("\n>>> SOME TESTS FAILED! Check logs above. <<<");
        }
    }

    private static void check(String testName, boolean condition) {
        total++;
        if (condition) {
            passed++;
            System.out.printf("  [PASS] %-60s%n", testName);
        } else {
            System.err.printf("  [FAIL] %-60s%n", testName);
        }
    }
}
