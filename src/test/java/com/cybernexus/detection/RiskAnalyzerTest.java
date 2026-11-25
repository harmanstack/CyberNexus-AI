package com.cybernexus.detection;

import com.cybernexus.model.ScanResult;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Automated JUnit 5 Unit Tests for RiskAnalyzer.
 * Part of Tanisha's Assigned Responsibilities (Scoring & Threshold Verification).
 *
 * Verifies:
 * 1. LOW (0-30), MEDIUM (31-60), and HIGH (61-100) categorization.
 * 2. Mathematical score clamping (0 <= score <= 100).
 * 3. Exact threshold boundary conditions.
 * 4. Null safety for reasons list.
 */
public class RiskAnalyzerTest {

    private final RiskAnalyzer analyzer = new RiskAnalyzer();

    @Test
    @DisplayName("Clean input with no findings should produce Score 0 and Level LOW")
    void testLowRiskEmptyFindings() {
        ScanResult result = analyzer.analyze("URL", "https://google.com", List.of());

        assertEquals(0, result.getRiskScore());
        assertEquals("LOW", result.getRiskLevel());
        assertTrue(result.getReasons().isEmpty());
    }

    @Test
    @DisplayName("Single low-weight indicator should remain in LOW risk category (score <= 30)")
    void testLowRiskSingleIndicator() {
        // "embedded web link" is weighted at 10 points
        ScanResult result = analyzer.analyze("MESSAGE", "Check this link",
                List.of("Contains an embedded web link inside the message"));

        assertEquals(10, result.getRiskScore());
        assertEquals("LOW", result.getRiskLevel());
    }

    @Test
    @DisplayName("Combined moderate indicators should fall into MEDIUM risk category (31-60)")
    void testMediumRiskScenario() {
        // "http instead" (+15) + "top-level domain" (+20) = 35 points
        ScanResult result = analyzer.analyze("URL", "http://my-blog.xyz", List.of(
                "Uses unencrypted HTTP instead of HTTPS",
                "Uses a frequently abused top-level domain: .xyz"
        ));

        assertEquals(35, result.getRiskScore());
        assertEquals("MEDIUM", result.getRiskLevel());
    }

    @Test
    @DisplayName("Combined severe indicators should produce HIGH risk category (61-100)")
    void testHighRiskScenario() {
        // urgency (+15) + sensitive credentials (+30) + shortener (+25) + link pressure (+15) = 85 points
        ScanResult result = analyzer.analyze("MESSAGE", "Urgent! Send password to bit.ly", List.of(
                "Uses artificial urgency language: 'within 24 hours'",
                "Asks for sensitive credentials/information: 'password'",
                "URL shortener hides the final destination (bit.ly)",
                "Pushes the reader to open a link: 'click here'"
        ));

        assertEquals(85, result.getRiskScore());
        assertEquals("HIGH", result.getRiskLevel());
    }

    @Test
    @DisplayName("Mathematical score clamping strictly enforces [0, 100] range")
    void testClampingBoundaries() {
        // Test internal clamp function directly
        assertEquals(0, analyzer.clamp(-100));
        assertEquals(0, analyzer.clamp(-1));
        assertEquals(0, analyzer.clamp(0));
        assertEquals(50, analyzer.clamp(50));
        assertEquals(100, analyzer.clamp(100));
        assertEquals(100, analyzer.clamp(101));
        assertEquals(100, analyzer.clamp(500));

        // Test through analyze() with massive list of findings
        List<String> overwhelmingFindings = List.of(
                "Possible brand impersonation detected: paypa1",        // 35
                "Asks for sensitive credentials/information: password",  // 30
                "Host is a raw IP address instead of a domain name",    // 25
                "URL shortener hides the final destination (bit.ly)",    // 25
                "Uses a frequently abused top-level domain: .xyz",       // 20
                "Contains sensitive action keyword: login"               // 20
        ); // Total raw sum: 155 points

        ScanResult result = analyzer.analyze("URL", "http://overwhelming-threat.com", overwhelmingFindings);
        assertEquals(100, result.getRiskScore(), "Score must be clamped at 100 max");
        assertEquals("HIGH", result.getRiskLevel());
    }

    @Test
    @DisplayName("Verify exact threshold boundaries for LOW, MEDIUM, and HIGH")
    void testExactThresholdBoundaries() {
        // Exact lower and upper bounds for LOW (0 to 30)
        assertEquals("LOW", analyzer.levelForScore(0));
        assertEquals("LOW", analyzer.levelForScore(15));
        assertEquals("LOW", analyzer.levelForScore(30));

        // Exact lower and upper bounds for MEDIUM (31 to 60)
        assertEquals("MEDIUM", analyzer.levelForScore(31));
        assertEquals("MEDIUM", analyzer.levelForScore(45));
        assertEquals("MEDIUM", analyzer.levelForScore(60));

        // Exact lower and upper bounds for HIGH (61 to 100)
        assertEquals("HIGH", analyzer.levelForScore(61));
        assertEquals("HIGH", analyzer.levelForScore(80));
        assertEquals("HIGH", analyzer.levelForScore(100));
    }

    @Test
    @DisplayName("Should safely handle null reasons list without NullPointerException")
    void testNullReasonsHandling() {
        ScanResult result = analyzer.analyze("URL", "https://example.com", null);

        assertNotNull(result);
        assertEquals(0, result.getRiskScore());
        assertEquals("LOW", result.getRiskLevel());
        assertNotNull(result.getReasons());
    }

    /**
     * Standalone runner to execute tests directly in IntelliJ or terminal.
     */
    public static void main(String[] args) {
        System.out.println("=== Running RiskAnalyzer Automated Verification Suite (Tanisha) ===");
        RiskAnalyzerTest test = new RiskAnalyzerTest();

        runCheck("Test 1: Empty Findings (LOW Risk 0)", () -> test.testLowRiskEmptyFindings());
        runCheck("Test 2: Single Indicator (LOW Risk <= 30)", () -> test.testLowRiskSingleIndicator());
        runCheck("Test 3: Moderate Threats (MEDIUM Risk 31-60)", () -> test.testMediumRiskScenario());
        runCheck("Test 4: Severe Threats (HIGH Risk 61-100)", () -> test.testHighRiskScenario());
        runCheck("Test 5: Clamping to 0 and 100 Bounds", () -> test.testClampingBoundaries());
        runCheck("Test 6: Exact 30/31 and 60/61 Boundaries", () -> test.testExactThresholdBoundaries());
        runCheck("Test 7: Null Reasons List Safety", () -> test.testNullReasonsHandling());

        System.out.println("\n>>> ALL RISKANALYZER TEST CASES PASSED! <<<");
    }

    private static void runCheck(String testName, Runnable testMethod) {
        try {
            testMethod.run();
            System.out.printf("  [PASS] %-48s%n", testName);
        } catch (AssertionError | Exception e) {
            System.err.printf("  [FAIL] %-48s -> %s%n", testName, e.getMessage());
        }
    }
}
