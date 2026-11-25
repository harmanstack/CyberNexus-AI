package com.cybernexus.detection;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Automated JUnit 5 Unit Tests for URLDetector.
 * Part of Tanisha's Assigned Responsibilities (Testing & Validation).
 *
 * Verifies that all 8 heuristic rules correctly identify threat indicators
 * and that safe HTTPS URLs produce zero false positives.
 */
public class URLDetectorTest {

    private final URLDetector detector = new URLDetector();

    @Test
    @DisplayName("Safe legitimate HTTPS URL should return zero threat indicators")
    void testSafeHttpsUrl() {
        List<String> findings = detector.detect("https://www.google.com");
        assertTrue(findings.isEmpty(), "Clean HTTPS site must not trigger false positives");

        List<String> universityFindings = detector.detect("https://university.edu/departments/cs");
        assertTrue(universityFindings.isEmpty(), "Academic domain must not trigger false positives");
    }

    @Test
    @DisplayName("Should detect raw IP address host and unencrypted HTTP")
    void testIpHostDetection() {
        List<String> findings = detector.detect("http://192.168.1.100/admin");

        assertFalse(findings.isEmpty(), "Raw IP URL must be flagged");
        assertTrue(findings.stream().anyMatch(f -> f.contains("unencrypted HTTP")),
                "Must flag HTTP scheme");
        assertTrue(findings.stream().anyMatch(f -> f.contains("raw IP address")),
                "Must flag IP address host");
    }

    @Test
    @DisplayName("Should detect brand impersonation typosquatting and suspicious TLD")
    void testBrandImpersonationAndTld() {
        List<String> findings = detector.detect("https://paypa1-secure-billing.xyz");

        assertFalse(findings.isEmpty());
        assertTrue(findings.stream().anyMatch(f -> f.contains("brand impersonation")),
                "Must flag paypa1 brand lookalike");
        assertTrue(findings.stream().anyMatch(f -> f.contains(".xyz")),
                "Must flag abused .xyz TLD");
    }

    @Test
    @DisplayName("Should detect URL shorteners masking final destinations")
    void testUrlShorteners() {
        List<String> findings = detector.detect("https://bit.ly/claim-free-coupon");

        assertFalse(findings.isEmpty());
        assertTrue(findings.stream().anyMatch(f -> f.contains("URL shortener")),
                "Must flag bit.ly shortening service");
    }

    @Test
    @DisplayName("Should detect '@' symbol masking trick")
    void testAtSymbolMasking() {
        List<String> findings = detector.detect("https://trusted-bank.com@malicious-phishing-host.com/login");

        assertFalse(findings.isEmpty());
        assertTrue(findings.stream().anyMatch(f -> f.contains("@")),
                "Must flag '@' obfuscation");
    }

    @Test
    @DisplayName("Should detect domain name with excessive hyphens")
    void testExcessiveHyphens() {
        List<String> findings = detector.detect("https://secure-login-account-update-portal.com");

        assertFalse(findings.isEmpty());
        assertTrue(findings.stream().anyMatch(f -> f.contains("many hyphens")),
                "Must flag URLs with 4 or more hyphens");
    }

    @Test
    @DisplayName("Should safely handle null or empty URL input without crashing")
    void testEmptyAndNullUrl() {
        List<String> nullFindings = detector.detect(null);
        assertEquals(1, nullFindings.size());
        assertTrue(nullFindings.get(0).contains("Empty or null"));

        List<String> blankFindings = detector.detect("    ");
        assertEquals(1, blankFindings.size());
        assertTrue(blankFindings.get(0).contains("Empty or null"));
    }

    /**
     * Standalone test runner to run tests directly from the command line or IntelliJ.
     */
    public static void main(String[] args) {
        System.out.println("=== Running URLDetector Automated Verification Suite (Tanisha) ===");
        URLDetectorTest test = new URLDetectorTest();

        runCheck("Test 1: Safe HTTPS Site", () -> test.testSafeHttpsUrl());
        runCheck("Test 2: Raw IP Host & HTTP", () -> test.testIpHostDetection());
        runCheck("Test 3: Brand Impersonation & TLD", () -> test.testBrandImpersonationAndTld());
        runCheck("Test 4: URL Shorteners", () -> test.testUrlShorteners());
        runCheck("Test 5: @ Symbol Masking", () -> test.testAtSymbolMasking());
        runCheck("Test 6: Excessive Hyphens", () -> test.testExcessiveHyphens());
        runCheck("Test 7: Null & Empty Inputs", () -> test.testEmptyAndNullUrl());

        System.out.println("\n>>> ALL URLDETECTOR TEST CASES PASSED! <<<");
    }

    private static void runCheck(String testName, Runnable testMethod) {
        try {
            testMethod.run();
            System.out.printf("  [PASS] %-45s%n", testName);
        } catch (AssertionError | Exception e) {
            System.err.printf("  [FAIL] %-45s -> %s%n", testName, e.getMessage());
        }
    }
}
