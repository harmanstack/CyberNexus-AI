package com.cybernexus.detection;

import com.cybernexus.model.ScanResult;
import com.cybernexus.service.AIService;

import java.util.List;

/**
 * Master End-to-End Test Suite for Tanisha's Cybersecurity Detection Engine.
 * Run directly in IntelliJ IDEA: Right-click -> Run 'DetectionEngineStandaloneTest.main()'
 *
 * Verifies all 5 core modules:
 * 1. URL Threat Detection
 * 2. Phishing Message Detection
 * 3. Weighted Risk Scoring & Clamping
 * 4. Threat Explanations & Security Recommendations
 * 5. Full End-to-End Pipeline Integration
 */
public class DetectionEngineStandaloneTest {

    private static int passed = 0;
    private static int total = 0;

    public static void main(String[] args) {
        System.out.println("===============================================================================");
        System.out.println("   CYBERNEXUS AI - TANISHA DETECTION ENGINE MASTER TEST SUITE (EVALUATION 1)");
        System.out.println("===============================================================================\n");

        URLDetector urlDetector = new URLDetector();
        MessageDetector messageDetector = new MessageDetector();
        RiskAnalyzer analyzer = new RiskAnalyzer();
        AIService aiService = new AIService();

        // -------------------------------------------------------------
        // GROUP 1: URL Threat Detection Rules
        // -------------------------------------------------------------
        System.out.println("[TEST GROUP 1] URL Threat Detection Heuristics");
        List<String> cleanUrl = urlDetector.detect("https://www.google.com");
        check("Clean HTTPS URL produces zero findings", cleanUrl.isEmpty());

        List<String> ipUrl = urlDetector.detect("http://192.168.1.100/login");
        check("Raw IP host + HTTP flagged", ipUrl.contains("Host is a raw IP address instead of a domain name")
                && ipUrl.contains("Uses unencrypted HTTP instead of HTTPS"));

        List<String> typoUrl = urlDetector.detect("https://paypa1-update-verify.xyz");
        check("Brand typosquatting + abused TLD flagged", typoUrl.stream().anyMatch(f -> f.contains("paypa1"))
                && typoUrl.stream().anyMatch(f -> f.contains(".xyz")));

        List<String> shortUrl = urlDetector.detect("https://bit.ly/secure-gift");
        check("URL shortener masked domain flagged", shortUrl.stream().anyMatch(f -> f.contains("bit.ly")));

        List<String> atUrl = urlDetector.detect("https://bank.com@malicious.com/account");
        check("@ symbol destination obfuscation flagged", atUrl.stream().anyMatch(f -> f.contains("@")));

        List<String> nullUrl = urlDetector.detect(null);
        check("Null URL handled safely without crash", nullUrl.size() == 1 && nullUrl.get(0).contains("Empty or null"));
        System.out.println();

        // -------------------------------------------------------------
        // GROUP 2: Phishing Message Detection Rules
        // -------------------------------------------------------------
        System.out.println("[TEST GROUP 2] Phishing Message Social Engineering Heuristics");
        List<String> cleanMsg = messageDetector.detect("Hey, are we still studying together for the exam tonight?");
        check("Normal message produces zero findings", cleanMsg.isEmpty());

        List<String> urgencyMsg = messageDetector.detect("URGENT: Your bank account will be suspended within 24 hours!");
        check("Artificial urgency and threats flagged", urgencyMsg.stream().anyMatch(f -> f.contains("urgency language")));

        List<String> credMsg = messageDetector.detect("Please reply immediately with your password and OTP code.");
        check("Credential harvesting (password, OTP) flagged", credMsg.stream().anyMatch(f -> f.contains("sensitive credentials")));

        List<String> lotteryMsg = messageDetector.detect("Congratulations! You have won a $1,000,000 lottery prize. Claim now!");
        check("Advance-fee lottery/prize scam flagged", lotteryMsg.stream().anyMatch(f -> f.contains("prize, reward, or lottery")));

        List<String> linkMsg = messageDetector.detect("Click here to resolve your issue: http://bit.ly/fix");
        check("Link pressure + embedded URL flagged", linkMsg.stream().anyMatch(f -> f.contains("open a link"))
                && linkMsg.stream().anyMatch(f -> f.contains("embedded web link")));

        List<String> paymentMsg = messageDetector.detect("Unauthorized transaction detected. Send wire transfer or gift card.");
        check("Suspicious financial/wire payment demands flagged", paymentMsg.stream().anyMatch(f -> f.contains("payment request")));

        List<String> nullMsg = messageDetector.detect("   ");
        check("Blank message handled safely without crash", nullMsg.size() == 1 && nullMsg.get(0).contains("Empty or null"));
        System.out.println();

        // -------------------------------------------------------------
        // GROUP 3: Risk Scoring & Clamping Engine
        // -------------------------------------------------------------
        System.out.println("[TEST GROUP 3] Weighted Risk Scoring, Thresholds, & Clamping");
        ScanResult lowRes = analyzer.analyze("URL", "https://google.com", List.of());
        check("Empty findings -> Score 0, Level LOW", lowRes.getRiskScore() == 0 && "LOW".equals(lowRes.getRiskLevel()));

        ScanResult medRes = analyzer.analyze("URL", "http://my-blog.xyz", List.of(
                "Uses unencrypted HTTP instead of HTTPS",
                "Uses a frequently abused top-level domain: .xyz"
        ));
        check("Moderate findings (35 pts) -> Level MEDIUM", medRes.getRiskScore() == 35 && "MEDIUM".equals(medRes.getRiskLevel()));

        ScanResult highRes = analyzer.analyze("MESSAGE", "Urgent phishing", List.of(
                "Uses artificial urgency language: 'within 24 hours'",
                "Asks for sensitive credentials/information: 'password'",
                "URL shortener hides the final destination (bit.ly)",
                "Pushes the reader to open a link: 'click here'"
        ));
        check("Severe findings (85 pts) -> Level HIGH", highRes.getRiskScore() == 85 && "HIGH".equals(highRes.getRiskLevel()));

        check("Clamping: -25 clamps to 0", analyzer.clamp(-25) == 0);
        check("Clamping: 145 clamps to 100", analyzer.clamp(145) == 100);
        check("Boundary: Score 30 is LOW", "LOW".equals(analyzer.levelForScore(30)));
        check("Boundary: Score 31 is MEDIUM", "MEDIUM".equals(analyzer.levelForScore(31)));
        check("Boundary: Score 60 is MEDIUM", "MEDIUM".equals(analyzer.levelForScore(60)));
        check("Boundary: Score 61 is HIGH", "HIGH".equals(analyzer.levelForScore(61)));
        System.out.println();

        // -------------------------------------------------------------
        // GROUP 4: Threat Explanations & Security Tips
        // -------------------------------------------------------------
        System.out.println("[TEST GROUP 4] Threat Explanations & Actionable Guidance");
        String lowExplanation = aiService.explain(lowRes);
        check("LOW risk explanation recommends general caution", lowExplanation.contains("No strong phishing indicators"));

        String highExplanation = aiService.explain(highRes);
        check("HIGH risk explanation provides defensive actions", highExplanation.contains("Do not open the link or reply"));
        System.out.println();

        // -------------------------------------------------------------
        // GROUP 5: End-to-End Pipeline Integration
        // -------------------------------------------------------------
        System.out.println("[TEST GROUP 5] Full End-to-End Pipeline Integration");
        String testPhishUrl = "http://192.168.1.50/paypa1-login-verify.xyz";
        List<String> pipelineFindings = urlDetector.detect(testPhishUrl);
        ScanResult pipelineResult = analyzer.analyze(urlDetector.getType(), testPhishUrl, pipelineFindings);
        pipelineResult.setExplanation(aiService.explain(pipelineResult));

        check("Pipeline: Correct Scan Type 'URL'", "URL".equals(pipelineResult.getScanType()));
        check("Pipeline: High threat score (>= 61)", pipelineResult.getRiskScore() >= 61);
        check("Pipeline: Correct Risk Level 'HIGH'", "HIGH".equals(pipelineResult.getRiskLevel()));
        check("Pipeline: Explanation populated", pipelineResult.getExplanation() != null && !pipelineResult.getExplanation().isBlank());
        check("Pipeline: Joined reasons formatted cleanly", pipelineResult.joinedReasons().contains(" | "));
        System.out.println();

        // -------------------------------------------------------------
        // FINAL SUMMARY REPORT
        // -------------------------------------------------------------
        System.out.println("===============================================================================");
        System.out.printf("   FINAL TEST RESULTS: %d / %d TESTS PASSED (%.1f%%)%n",
                passed, total, (passed * 100.0 / total));
        System.out.println("===============================================================================");

        if (passed == total) {
            System.out.println("\n>>> ALL TANISHA DETECTION ENGINE MODULES VERIFIED SUCCESSFULLY! <<<");
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
