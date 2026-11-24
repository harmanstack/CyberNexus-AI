package com.cybernexus;

import com.cybernexus.config.DBConnection;
import com.cybernexus.dao.ScanDAO;
import com.cybernexus.dao.UserDAO;
import com.cybernexus.model.Scan;
import com.cybernexus.model.User;
import com.cybernexus.service.AuthService;
import com.cybernexus.util.PasswordUtil;

import java.time.LocalDateTime;

/**
 * Standalone Backend Test Suite for Harman's Evaluation 1.
 * Run this directly in IntelliJ IDEA: Right-click -> Run 'BackendStandaloneTest.main()'
 *
 * Tests every backend class independently and outputs a formatted verification report.
 */
public class BackendStandaloneTest {

    private static int testsPassed = 0;
    private static int testsTotal = 0;

    public static void main(String[] args) {
        System.out.println("=======================================================================");
        System.out.println("   CYBERNEXUS AI - HARMAN BACKEND TEST SUITE (EVALUATION 1)");
        System.out.println("=======================================================================\n");

        testUserModel();
        testPasswordHashing();
        testAuthServiceValidation();
        testScanModelAndDAOConstraints();
        testDBConfiguration();

        System.out.println("\n=======================================================================");
        System.out.printf("   FINAL TEST RESULTS: %d / %d TESTS PASSED (%.1f%%)%n",
                testsPassed, testsTotal, (testsPassed * 100.0 / testsTotal));
        System.out.println("=======================================================================");

        if (testsPassed == testsTotal) {
            System.out.println("\n>>> ALL HARMAN BACKEND MODULES VERIFIED SUCCESSFULLY! <<<");
        } else {
            System.err.println("\n>>> SOME BACKEND TESTS FAILED! Check logs above. <<<");
        }
    }

    private static void testUserModel() {
        System.out.println("[TEST GROUP 1] User Model Encapsulation & Security");
        LocalDateTime created = LocalDateTime.now();
        User user = new User(101, "Harman", "harman@cybernexus.com", "$2a$10$abcdef", "admin", created);

        assertCheck("User ID getter matches", user.getId() == 101 && user.getUserId() == 101);
        assertCheck("Username getter matches", "Harman".equals(user.getName()) && "Harman".equals(user.getUsername()));
        assertCheck("Email getter matches", "harman@cybernexus.com".equals(user.getEmail()));
        assertCheck("isAdmin() returns true for admin", user.isAdmin());

        user.setRole("user");
        assertCheck("isAdmin() returns false for standard user", !user.isAdmin());

        String str = user.toString();
        assertCheck("toString() masks password hash", str.contains("[PROTECTED]") && !str.contains("$2a$10$abcdef"));
        System.out.println();
    }

    private static void testPasswordHashing() {
        System.out.println("[TEST GROUP 2] BCrypt Password Security (PasswordUtil)");
        String password = "MySecurePassword2026";
        String hash1 = PasswordUtil.hash(password);
        String hash2 = PasswordUtil.hash(password);

        assertCheck("BCrypt hash length is strictly 60 chars", hash1 != null && hash1.length() == 60);
        assertCheck("Salting: Hashes for same password are unique", !hash1.equals(hash2));
        assertCheck("Correct password matches hash", PasswordUtil.matches(password, hash1));
        assertCheck("Wrong password fails match", !PasswordUtil.matches("WrongPass123", hash1));
        assertCheck("Null/empty input safely returns false", !PasswordUtil.matches(null, hash1) && !PasswordUtil.matches(password, null));
        System.out.println();
    }

    private static void testAuthServiceValidation() {
        System.out.println("[TEST GROUP 3] AuthService Business Rules & Input Validation");
        AuthService authService = new AuthService();

        // Test short password rejection
        boolean caughtShortPassword = false;
        try {
            authService.register("ValidUser", "valid@email.com", "short");
        } catch (IllegalArgumentException e) {
            caughtShortPassword = true;
        } catch (Exception ignored) {
        }
        assertCheck("AuthService rejects password < 8 characters", caughtShortPassword);

        // Test invalid email rejection
        boolean caughtBadEmail = false;
        try {
            authService.register("ValidUser", "not-an-email", "Password123");
        } catch (IllegalArgumentException e) {
            caughtBadEmail = true;
        } catch (Exception ignored) {
        }
        assertCheck("AuthService rejects malformed email", caughtBadEmail);

        // Test space in password rejection
        boolean caughtSpacePassword = false;
        try {
            authService.register("ValidUser", "valid@email.com", "Pass word 123");
        } catch (IllegalArgumentException e) {
            caughtSpacePassword = true;
        } catch (Exception ignored) {
        }
        assertCheck("AuthService rejects passwords with whitespace", caughtSpacePassword);
        System.out.println();
    }

    private static void testScanModelAndDAOConstraints() {
        System.out.println("[TEST GROUP 4] Scan Model & ScanDAO Constraints");
        Scan scan = new Scan(1, "URL", "https://malicious-login-check.com", 85, "HIGH", "Matched suspicious keywords");

        assertCheck("Scan userId matches", scan.getUserId() == 1);
        assertCheck("Scan risk score matches", scan.getRiskScore() == 85);
        assertCheck("Scan risk level matches", "HIGH".equals(scan.getRiskLevel()));

        ScanDAO dao = new ScanDAO();
        boolean caughtInvalidRiskScore = false;
        try {
            scan.setRiskScore(150); // Invalid score (> 100)
            dao.saveScan(scan);
        } catch (IllegalArgumentException e) {
            caughtInvalidRiskScore = true;
        } catch (Exception ignored) {
        }
        assertCheck("ScanDAO rejects risk score > 100", caughtInvalidRiskScore);
        System.out.println();
    }

    private static void testDBConfiguration() {
        System.out.println("[TEST GROUP 5] DBConnection Setup & Diagnostics");
        try {
            // Verify DBConnection class loads without throwing IllegalStateException
            Class.forName("com.cybernexus.config.DBConnection");
            assertCheck("DBConnection class and MySQL Driver loaded successfully", true);
        } catch (Exception e) {
            assertCheck("DBConnection class loaded successfully", false);
        }
        System.out.println();
    }

    private static void assertCheck(String testName, boolean condition) {
        testsTotal++;
        if (condition) {
            testsPassed++;
            System.out.printf("  [PASS] %-55s%n", testName);
        } else {
            System.err.printf("  [FAIL] %-55s%n", testName);
        }
    }
}
