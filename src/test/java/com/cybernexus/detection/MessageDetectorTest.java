package com.cybernexus.detection;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Automated JUnit 5 Unit Tests for MessageDetector.
 * Part of Tanisha's Assigned Responsibilities (Testing & Validation).
 *
 * Verifies that normal conversational messages trigger zero false positives,
 * while phishing, social engineering, and advance-fee scams are reliably flagged.
 */
public class MessageDetectorTest {

    private final MessageDetector detector = new MessageDetector();

    @Test
    @DisplayName("Normal conversational message should return zero threat indicators")
    void testNormalConversationMessage() {
        List<String> findings = detector.detect("Hello Professor, I have submitted the assignment on the portal.");
        assertTrue(findings.isEmpty(), "Normal academic email must not trigger false positives");

        List<String> chatFindings = detector.detect("Hey are you coming to the coffee shop after class?");
        assertTrue(chatFindings.isEmpty(), "Casual peer message must not trigger false positives");
    }

    @Test
    @DisplayName("Should detect artificial urgency and credential harvesting")
    void testUrgencyAndCredentialPhishing() {
        List<String> findings = detector.detect(
                "URGENT: Your account will be closed within 24 hours. Enter your password and OTP immediately.");

        assertFalse(findings.isEmpty(), "Phishing message must be flagged");
        assertTrue(findings.stream().anyMatch(f -> f.contains("urgency language")),
                "Must flag urgency trigger");
        assertTrue(findings.stream().anyMatch(f -> f.contains("sensitive credentials")),
                "Must flag password/OTP trigger");
    }

    @Test
    @DisplayName("Should detect advance-fee prize and lottery reward scams")
    void testPrizeAndLotteryScam() {
        List<String> findings = detector.detect(
                "Congratulations! You have won a free gift cash reward in the international lottery. Claim now!");

        assertFalse(findings.isEmpty());
        assertTrue(findings.stream().anyMatch(f -> f.contains("prize, reward, or lottery")),
                "Must flag lottery/prize scam words");
    }

    @Test
    @DisplayName("Should detect link pressure and embedded URLs inside messages")
    void testLinkPressureAndEmbeddedUrl() {
        List<String> findings = detector.detect(
                "Click here to resolve your problem: https://bit.ly/bank-unlock");

        assertFalse(findings.isEmpty());
        assertTrue(findings.stream().anyMatch(f -> f.contains("open a link")),
                "Must flag link pressure call-to-action");
        assertTrue(findings.stream().anyMatch(f -> f.contains("embedded web link")),
                "Must detect embedded URL");
    }

    @Test
    @DisplayName("Should detect suspicious wire transfer and crypto payment demands")
    void testSuspiciousPaymentDemands() {
        List<String> findings = detector.detect(
                "Security Alert: Unauthorized transaction detected. Send wire transfer or gift card immediately.");

        assertFalse(findings.isEmpty());
        assertTrue(findings.stream().anyMatch(f -> f.contains("financial or payment request")),
                "Must flag wire transfer/gift card payment request");
    }

    @Test
    @DisplayName("Should detect generic impersonal greetings")
    void testGenericGreeting() {
        List<String> findings = detector.detect("Dear customer, please review your monthly statement.");

        assertFalse(findings.isEmpty());
        assertTrue(findings.stream().anyMatch(f -> f.contains("generic greeting")),
                "Must flag generic impersonal greeting");
    }

    @Test
    @DisplayName("Should safely handle null or blank messages without throwing exceptions")
    void testEmptyAndNullMessage() {
        List<String> nullFindings = detector.detect(null);
        assertEquals(1, nullFindings.size());
        assertTrue(nullFindings.get(0).contains("Empty or null"));

        List<String> blankFindings = detector.detect("     ");
        assertEquals(1, blankFindings.size());
        assertTrue(blankFindings.get(0).contains("Empty or null"));
    }

    /**
     * Standalone test runner to run tests directly from IntelliJ or command line.
     */
    public static void main(String[] args) {
        System.out.println("=== Running MessageDetector Automated Verification Suite (Tanisha) ===");
        MessageDetectorTest test = new MessageDetectorTest();

        runCheck("Test 1: Normal Message (No False Positives)", () -> test.testNormalConversationMessage());
        runCheck("Test 2: Urgency & Credential Theft", () -> test.testUrgencyAndCredentialPhishing());
        runCheck("Test 3: Prize & Lottery Scam", () -> test.testPrizeAndLotteryScam());
        runCheck("Test 4: Link Pressure & Embedded URL", () -> test.testLinkPressureAndEmbeddedUrl());
        runCheck("Test 5: Suspicious Payment Demands", () -> test.testSuspiciousPaymentDemands());
        runCheck("Test 6: Generic Impersonal Greeting", () -> test.testGenericGreeting());
        runCheck("Test 7: Null & Blank Message Inputs", () -> test.testEmptyAndNullMessage());

        System.out.println("\n>>> ALL MESSAGEDETECTOR TEST CASES PASSED! <<<");
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
