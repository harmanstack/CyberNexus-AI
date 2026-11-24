package com.cybernexus.console;

import com.cybernexus.dao.ScanDAO;
import com.cybernexus.dao.UserDAO;
import com.cybernexus.model.Scan;
import com.cybernexus.model.User;
import com.cybernexus.util.InputValidator;

import java.sql.SQLException;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

/** Admin-only statistics and scan reports (Evaluation 2 / Harman phase 2). */
public class AdminMenu {
    private final Scanner scanner;
    private final UserDAO userDAO;
    private final ScanDAO scanDAO;

    public AdminMenu(Scanner scanner) {
        this(scanner, new UserDAO(), new ScanDAO());
    }

    public AdminMenu(Scanner scanner, UserDAO userDAO, ScanDAO scanDAO) {
        this.scanner = scanner;
        this.userDAO = userDAO;
        this.scanDAO = scanDAO;
    }

    public void show(User admin) {
        boolean running = true;
        while (running) {
            System.out.println();
            System.out.println("==== Admin menu (" + admin.getName() + ") ====");
            System.out.println("1. User and scan statistics");
            System.out.println("2. All scan reports");
            System.out.println("3. Logout");
            System.out.print("Choose: ");
            try {
                int choice = InputValidator.requireMenuChoice(scanner.nextLine(), 1, 3);
                switch (choice) {
                    case 1 -> printStatistics();
                    case 2 -> printAllScans();
                    case 3 -> running = false;
                    default -> System.out.println("Unknown option.");
                }
            } catch (IllegalArgumentException exception) {
                System.out.println("Input error: " + exception.getMessage());
            } catch (SQLException exception) {
                System.out.println("Database error: " + exception.getMessage());
            }
        }
    }

    private void printStatistics() throws SQLException {
        System.out.println("Total users: " + userDAO.countUsers());
        System.out.println("Total scans: " + scanDAO.countScans());
        System.out.println("--- Per user (JOIN users LEFT JOIN scans) ---");
        List<Map<String, Object>> rows = scanDAO.userScanStatistics();
        for (Map<String, Object> row : rows) {
            System.out.printf("%s <%s> role=%s scans=%s avg=%.1f high=%s%n",
                    row.get("name"),
                    row.get("email"),
                    row.get("role"),
                    row.get("scanCount"),
                    (Double) row.get("averageScore"),
                    row.get("highCount"));
        }
    }

    private void printAllScans() throws SQLException {
        List<Scan> scans = scanDAO.findAll();
        if (scans.isEmpty()) {
            System.out.println("No scans in the database.");
            return;
        }
        for (Scan scan : scans) {
            System.out.printf("#%d user=%d %s %s %d/100%n  %s%n  %s%n",
                    scan.getId(),
                    scan.getUserId(),
                    scan.getScanType(),
                    scan.getRiskLevel(),
                    scan.getRiskScore(),
                    scan.getInputData(),
                    scan.getDetectionReason());
        }
    }
}
