package com.cybernexus.console;

import com.cybernexus.model.Scan;
import com.cybernexus.model.ScanResult;
import com.cybernexus.model.User;
import com.cybernexus.service.AIService;
import com.cybernexus.service.ScanService;
import com.cybernexus.util.InputValidator;

import java.sql.SQLException;
import java.util.List;
import java.util.Scanner;

/** Logged-in user menu from the assignment: scan, history, tips, AI explanation. */
public class Dashboard {
    private static final String[] TIPS = {
            "Never send passwords, OTPs, or bank details in a chat or email.",
            "Type official websites yourself instead of clicking unexpected links.",
            "Check the spelling of the domain before you sign in.",
            "Enable multi-factor authentication on important accounts.",
            "If a message creates panic, pause and verify through another channel."
    };

    private final Scanner scanner;
    private final ScanService scanService;
    private ScanResult lastResult;

    public Dashboard(Scanner scanner, ScanService scanService) {
        this.scanner = scanner;
        this.scanService = scanService;
    }

    public void show(User user) {
        boolean running = true;
        while (running) {
            System.out.println();
            System.out.println("==== User dashboard (" + user.getName() + ") ====");
            System.out.println("1. Scan suspicious URL");
            System.out.println("2. Scan suspicious messages");
            System.out.println("3. View scan history");
            System.out.println("4. Cyber security tips");
            System.out.println("5. AI threat explanation");
            System.out.println("6. Logout");
            System.out.print("Choose: ");
            try {
                int choice = InputValidator.requireMenuChoice(scanner.nextLine(), 1, 6);
                switch (choice) {
                    case 1 -> lastResult = runUrlScan(user);
                    case 2 -> lastResult = runMessageScan(user);
                    case 3 -> showHistory(user);
                    case 4 -> showTips();
                    case 5 -> showExplanation();
                    case 6 -> running = false;
                    default -> System.out.println("Unknown option.");
                }
            } catch (IllegalArgumentException exception) {
                System.out.println("Input error: " + exception.getMessage());
            } catch (SQLException exception) {
                System.out.println("Database error: " + exception.getMessage());
            }
        }
    }

    private ScanResult runUrlScan(User user) throws SQLException {
        System.out.print("Enter URL: ");
        ScanResult result = scanService.scanUrl(user, scanner.nextLine());
        printResult(result);
        return result;
    }

    private ScanResult runMessageScan(User user) throws SQLException {
        System.out.print("Paste the message: ");
        ScanResult result = scanService.scanMessage(user, scanner.nextLine());
        printResult(result);
        return result;
    }

    private void showHistory(User user) throws SQLException {
        List<Scan> history = scanService.historyFor(user);
        if (history.isEmpty()) {
            System.out.println("No scans saved yet.");
            return;
        }
        System.out.println("--- Scan history ---");
        for (Scan scan : history) {
            System.out.printf("#%d | %s | %s | %d/100 | %s%n",
                    scan.getId(),
                    scan.getScanType(),
                    scan.getRiskLevel(),
                    scan.getRiskScore(),
                    scan.getCreatedAt());
            System.out.println("  Input : " + scan.getInputData());
            System.out.println("  Reason: " + scan.getDetectionReason());
        }
    }

    private void showTips() {
        System.out.println("--- Cyber security tips ---");
        for (int i = 0; i < TIPS.length; i++) {
            System.out.println((i + 1) + ". " + TIPS[i]);
        }
    }

    private void showExplanation() {
        if (lastResult == null) {
            System.out.println("Run a scan first, or type a URL/message to explain.");
            System.out.print("Enter text (or blank to cancel): ");
            String input = scanner.nextLine();
            if (InputValidator.isBlank(input)) {
                return;
            }
            String type = InputValidator.looksLikeUrl(input) ? "URL" : "MESSAGE";
            lastResult = scanService.explainOnly(type, input.trim());
        }
        System.out.println("--- AI threat explanation ---");
        System.out.println(lastResult.getExplanation());
        System.out.println("Recommendation: "
                + new AIService().recommendationFor(lastResult.getRiskLevel()));
    }

    private void printResult(ScanResult result) {
        System.out.println("Risk score : " + result.getRiskScore() + " / 100");
        System.out.println("Risk level : " + result.getRiskLevel());
        System.out.println("Reasons    : " + result.joinedReasons());
        System.out.println("Explanation: " + result.getExplanation());
    }
}
