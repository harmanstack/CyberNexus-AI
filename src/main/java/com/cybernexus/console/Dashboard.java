package com.cybernexus.console;

import com.cybernexus.model.Scan;
import com.cybernexus.model.ScanResult;
import com.cybernexus.model.User;
import com.cybernexus.service.ScanService;
import com.cybernexus.util.InputValidator;

import java.sql.SQLException;
import java.util.List;
import java.util.Scanner;

/**
 * Terminal User Dashboard for logged-in users.
 *
 * Coordinates:
 * 1. URL Threat Scanning (delegates to ScanService -> URLDetector -> RiskAnalyzer -> ScanDAO).
 * 2. Message Threat Scanning (delegates to ScanService -> MessageDetector -> RiskAnalyzer -> ScanDAO).
 * 3. Scan History Retrieval (delegates to ScanService -> ScanDAO).
 * 4. Cybersecurity Awareness Tips.
 * 5. Session Logout.
 */
public class Dashboard {

    private static final String[] CYBER_TIPS = {
            "Never share sensitive credentials, OTPs, or passwords over email or SMS.",
            "Verify URLs carefully: check for typosquatting (e.g., paypa1 vs paypal) and unencrypted HTTP.",
            "Beware of artificial urgency: attackers create panic (e.g., 'within 24 hours') to rush mistakes.",
            "Avoid clicking shortened links (bit.ly, tinyurl) from unknown or unsolicited senders.",
            "Always enable Multi-Factor Authentication (MFA) across your critical accounts."
    };

    private final Scanner scanner;
    private final ScanService scanService;

    public Dashboard() {
        this(new Scanner(System.in), new ScanService());
    }

    public Dashboard(Scanner scanner, ScanService scanService) {
        this.scanner = scanner;
        this.scanService = scanService;
    }

    /**
     * Launches the dashboard loop for the authenticated user.
     *
     * @param user current authenticated user session
     */
    public void show(User user) {
        boolean loggedIn = true;

        while (loggedIn) {
            displayDashboardMenu(user);

            try {
                System.out.print("Select an option: ");
                int choice = InputValidator.requireMenuChoice(scanner.nextLine(), 1, 5);

                switch (choice) {
                    case 1 -> handleUrlScan(user);
                    case 2 -> handleMessageScan(user);
                    case 3 -> handleViewHistory(user);
                    case 4 -> handleCyberTips();
                    case 5 -> {
                        loggedIn = false;
                        System.out.println("\n[INFO] Logged out successfully. Returning to welcome menu...");
                    }
                    default -> System.out.println("[WARN] Invalid option. Please choose between 1 and 5.");
                }
            } catch (IllegalArgumentException exception) {
                System.out.println("[INPUT ERROR] " + exception.getMessage());
            } catch (SQLException exception) {
                System.out.println("[DATABASE ERROR] Could not complete scan operation: " + exception.getMessage());
            } catch (Exception exception) {
                System.out.println("[ERROR] Unexpected error: " + exception.getMessage());
            }

            if (loggedIn) {
                System.out.println(); // Formatting spacing between dashboard actions
            }
        }
    }

    /**
     * Displays the User Dashboard menu header.
     */
    private void displayDashboardMenu(User user) {
        System.out.println("====================================");
        System.out.println("          USER DASHBOARD            ");
        System.out.println("====================================");
        System.out.println(" Logged in as: " + user.getName() + " (" + user.getEmail() + ")");
        System.out.println("------------------------------------");
        System.out.println("1. Scan Suspicious URL");
        System.out.println("2. Scan Suspicious Message");
        System.out.println("3. View Scan History");
        System.out.println("4. Cyber Security Tips");
        System.out.println("5. Logout");
        System.out.println("------------------------------------");
    }

    /**
     * Prompts for a URL and coordinates detection, scoring, and saving.
     */
    private void handleUrlScan(User user) throws SQLException {
        System.out.println("\n--- URL THREAT SCANNER ---");
        System.out.print("Enter URL to scan (e.g., https://example.com/login): ");
        String rawUrl = scanner.nextLine();

        if (InputValidator.isBlank(rawUrl)) {
            System.out.println("[WARN] URL cannot be empty.");
            return;
        }

        System.out.println("[*] Analyzing URL heuristics and threat vectors...");
        ScanResult result = scanService.scanUrl(user, rawUrl);
        printScanResultCard(result);
    }

    /**
     * Prompts for message text and coordinates social engineering detection, scoring, and saving.
     */
    private void handleMessageScan(User user) throws SQLException {
        System.out.println("\n--- PHISHING MESSAGE SCANNER ---");
        System.out.println("Paste or enter the suspicious message text below:");
        System.out.print("> ");
        String rawMessage = scanner.nextLine();

        if (InputValidator.isBlank(rawMessage)) {
            System.out.println("[WARN] Message text cannot be empty.");
            return;
        }

        System.out.println("[*] Analyzing message for psychological urgency and credential harvesting...");
        ScanResult result = scanService.scanMessage(user, rawMessage);
        printScanResultCard(result);
    }

    /**
     * Retrieves and renders the user's historical scans in an ASCII table format.
     */
    private void handleViewHistory(User user) throws SQLException {
        System.out.println("\n--- SCAN HISTORY FOR: " + user.getName() + " ---");
        List<Scan> history = scanService.historyFor(user);

        if (history == null || history.isEmpty()) {
            System.out.println("[INFO] No previous scans found for your account. Run a scan from Option 1 or 2!");
            return;
        }

        System.out.println("--------------------------------------------------------------------------------------------------------");
        System.out.printf(" %-5s | %-8s | %-10s | %-7s | %-19s | %-35s%n",
                "ID", "Type", "Risk Level", "Score", "Scan Date", "Target Input");
        System.out.println("--------------------------------------------------------------------------------------------------------");

        for (Scan scan : history) {
            String shortTarget = scan.getInputData() != null && scan.getInputData().length() > 35
                    ? scan.getInputData().substring(0, 32) + "..."
                    : (scan.getInputData() == null ? "N/A" : scan.getInputData());

            String dateStr = scan.getCreatedAt() != null ? scan.getCreatedAt().toString() : "N/A";
            if (dateStr.length() > 19) {
                dateStr = dateStr.substring(0, 19);
            }

            System.out.printf(" #%-4d | %-8s | %-10s | %3d/100 | %-19s | %-35s%n",
                    scan.getId(),
                    scan.getScanType(),
                    scan.getRiskLevel(),
                    scan.getRiskScore(),
                    dateStr,
                    shortTarget);

            if (scan.getDetectionReason() != null && !scan.getDetectionReason().isBlank()) {
                System.out.println("       Reasons: " + scan.getDetectionReason());
            }
        }
        System.out.println("--------------------------------------------------------------------------------------------------------");
        System.out.println(" Total Scans Recorded: " + history.size());
    }

    /**
     * Displays practical cybersecurity defensive tips.
     */
    private void handleCyberTips() {
        System.out.println("\n================================================================================");
        System.out.println("                       CYBER SECURITY DEFENSE TIPS                              ");
        System.out.println("================================================================================");
        for (int i = 0; i < CYBER_TIPS.length; i++) {
            System.out.printf(" %d. %s%n", (i + 1), CYBER_TIPS[i]);
        }
        System.out.println("================================================================================");
    }

    /**
     * Formats and prints a comprehensive security analysis card in the terminal.
     */
    private void printScanResultCard(ScanResult result) {
        System.out.println("\n================================================================================");
        System.out.println("                           THREAT ANALYSIS REPORT                               ");
        System.out.println("================================================================================");
        System.out.printf(" Scan Type   : %s%n", result.getScanType());
        System.out.printf(" Target      : %s%n", result.getInputData());
        System.out.printf(" Risk Score  : %d / 100%n", result.getRiskScore());
        System.out.printf(" Risk Level  : %s%n", result.getRiskLevel());

        if (result.getReasons() == null || result.getReasons().isEmpty()) {
            System.out.println(" Findings    : None detected (Safe pattern).");
        } else {
            System.out.printf(" Findings    : %s%n", result.joinedReasons());
        }

        if (result.getExplanation() != null && !result.getExplanation().isBlank()) {
            System.out.printf(" Advice      : %s%n", result.getExplanation());
        }
        System.out.println(" Status      : Saved to MySQL database successfully.");
        System.out.println("================================================================================");
    }
}
