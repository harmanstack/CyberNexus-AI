package com.cybernexus.detection;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * URLDetector implements rule-based heuristic threat detection for URLs.
 * Part of Tanisha's Assigned Responsibilities (Cybersecurity Detection Engine).
 *
 * Implements defensive checks:
 * 1. Unencrypted HTTP scheme
 * 2. Raw IP address hosts (bypassing DNS)
 * 3. Credential/obfuscation tokens (@ symbols)
 * 4. High-risk Top-Level Domains (TLDs)
 * 5. URL shortener obfuscation
 * 6. Brand impersonation / typosquatting
 * 7. Sensitive credential/banking keywords
 * 8. Structural anomalies (excessive hyphens, unusual length)
 */
public class URLDetector extends AbstractDetector {

    // Regex to detect raw IPv4 addresses in URLs (e.g., http://192.168.1.1/login)
    private static final Pattern IP_HOST = Pattern.compile(
            "(?i)https?://(?:\\d{1,3}\\.){3}\\d{1,3}");

    // Regex to detect embedded credentials or URL spoofing with @
    private static final Pattern CREDENTIAL_IN_URL = Pattern.compile(
            "(?i)https?://[^/]*:[^/]*@");

    // Frequently abused free or low-reputation top-level domains
    private static final String[] SUSPICIOUS_TLDS = {
            ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top"
    };

    // Common URL shortening services that mask destination domains
    private static final String[] SHORTENERS = {
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"
    };

    // Sensitive target action words commonly found in phishing landing pages
    private static final String[] SENSITIVE_WORDS = {
            "login", "signin", "verify", "secure", "update", "account",
            "password", "billing", "banking", "wallet"
    };

    // Typosquatting / Lookalike brand impersonation patterns
    private static final String[] BRAND_LOOKALIKES = {
            "paypa1", "paypai", "faceb00k", "micros0ft", "g00gle", "app1e-id", "netfIix", "amaz0n"
    };

    @Override
    public String getType() {
        return "URL";
    }

    /**
     * Inspects a URL string against predefined heuristic rules.
     *
     * @param input the raw URL entered by the user
     * @return a List of human-readable detection reasons
     */
    @Override
    public List<String> detect(String input) {
        List<String> findings = new ArrayList<>();

        if (input == null || input.isBlank()) {
            findings.add("Empty or null URL provided");
            return findings;
        }

        String url = lower(input).trim();

        // 1. Check for unencrypted HTTP
        if (url.startsWith("http://")) {
            findings.add("Uses unencrypted HTTP instead of HTTPS");
        }

        // 2. Check for raw IP address hostname
        if (IP_HOST.matcher(url).find()) {
            findings.add("Host is a raw IP address instead of a domain name");
        }

        // 3. Check for credential/redirect masking via '@' symbol
        if (url.contains("@") || CREDENTIAL_IN_URL.matcher(input).find()) {
            findings.add("URL contains '@' which can hide the real destination");
        }

        // 4. Check for high-risk TLDs
        for (String tld : SUSPICIOUS_TLDS) {
            if (url.contains(tld)) {
                findings.add("Uses a frequently abused top-level domain: " + tld);
                break;
            }
        }

        // 5. Check for URL shorteners
        for (String shortener : SHORTENERS) {
            if (url.contains(shortener)) {
                findings.add("URL shortener hides the final destination (" + shortener + ")");
                break;
            }
        }

        // 6. Check for excessive hyphens (common domain spoofing trick)
        int hyphens = countChar(url, '-');
        if (hyphens >= 4) {
            findings.add("Unusually many hyphens in the URL (" + hyphens + " hyphens)");
        }

        // 7. Check for sensitive credential action words
        for (String word : SENSITIVE_WORDS) {
            if (containsIgnoreCase(url, word)) {
                findings.add("Contains sensitive action keyword: " + word);
                break;
            }
        }

        // 8. Check for typosquatting / brand lookalikes
        for (String lookalike : BRAND_LOOKALIKES) {
            if (containsIgnoreCase(url, lookalike)) {
                findings.add("Possible brand impersonation detected: " + lookalike);
                break;
            }
        }

        // 9. Check for unusually long URLs
        if (url.length() > 120) {
            findings.add("URL is unusually long (" + url.length() + " characters)");
        }

        return findings;
    }

    /**
     * Utility method to count occurrences of a specific character in a string.
     */
    private int countChar(String text, char target) {
        int count = 0;
        for (int i = 0; i < text.length(); i++) {
            if (text.charAt(i) == target) {
                count++;
            }
        }
        return count;
    }

    /**
     * Standalone main method to demonstrate URL detection.
     * Right-click inside this file and select: Run 'URLDetector.main()'
     */
    public static void main(String[] args) {
        System.out.println("=== Testing URLDetector (Tanisha - Cybersecurity Engine) ===\n");

        URLDetector detector = new URLDetector();

        String[] testUrls = {
                "https://www.google.com",
                "http://192.168.1.50/login.html",
                "https://paypa1-security-update-verify-account.xyz",
                "http://bit.ly/claim-prize-now",
                "https://legit-site.com@evil-phishing-portal.com/banking"
        };

        for (String testUrl : testUrls) {
            System.out.println("Testing URL: " + testUrl);
            List<String> findings = detector.detect(testUrl);
            if (findings.isEmpty()) {
                System.out.println("  -> [CLEAN] No threat indicators detected.");
            } else {
                for (String reason : findings) {
                    System.out.println("  -> [FLAGGED] " + reason);
                }
            }
            System.out.println();
        }
    }
}
