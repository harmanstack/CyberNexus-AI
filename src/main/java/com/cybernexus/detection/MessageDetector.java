package com.cybernexus.detection;

import java.util.ArrayList;
import java.util.List;

/**
 * MessageDetector implements rule-based heuristic threat detection for text messages.
 * Part of Tanisha's Assigned Responsibilities (Cybersecurity Detection Engine).
 *
 * Implements defensive checks for:
 * 1. Artificial urgency and coercive deadlines
 * 2. Sensitive credential harvesting (passwords, OTPs, PINs)
 * 3. Advance-fee lottery, reward, and prize scams
 * 4. Call-to-action link pressure (click here, verify now)
 * 5. Suspicious payment/financial demands (crypto, wire transfer, gift cards)
 * 6. Embedded web links and shorteners
 * 7. Impersonal generic greetings (dear customer, valued member)
 */
public class MessageDetector extends AbstractDetector {

    // 1. Urgency and Threatening Language
    private static final String[] URGENCY = {
            "urgent", "immediately", "act now", "within 24 hours", "account will be closed",
            "suspended", "last chance", "immediate action required", "account locked",
            "security alert"
    };

    // 2. Sensitive Credential and Identity Theft Requests
    private static final String[] CREDENTIALS = {
            "password", "otp", "one-time password", "one-time pin", "pin", "ssn",
            "social security", "cvv", "bank details", "credit card", "security code"
    };

    // 3. Prize, Lottery, and Advance-Fee Reward Scams
    private static final String[] PRIZE = {
            "you have won", "lottery", "prize", "free gift", "claim now",
            "selected as winner", "congratulations you won", "cash reward", "million dollars"
    };

    // 4. Call-to-Action Link Pressure
    private static final String[] LINK_PRESSURE = {
            "click here", "click the link", "open this link", "verify here",
            "tap to unlock", "follow the link below", "update via link"
    };

    // 5. Suspicious Financial & Payment Requests
    private static final String[] PAYMENT_REQUESTS = {
            "wire transfer", "bitcoin", "crypto", "gift card", "overdue payment",
            "unauthorized transaction", "tax refund", "refund department"
    };

    // 6. Generic Impersonal Greetings
    private static final String[] GENERIC_GREETINGS = {
            "dear customer", "dear user", "valued customer", "dear client", "valued member"
    };

    @Override
    public String getType() {
        return "MESSAGE";
    }

    /**
     * Inspects a text message against predefined heuristic phishing rules.
     *
     * @param input the raw text message entered by the user
     * @return a List of human-readable detection reasons
     */
    @Override
    public List<String> detect(String input) {
        List<String> findings = new ArrayList<>();

        if (input == null || input.isBlank()) {
            findings.add("Empty or null message provided");
            return findings;
        }

        String text = lower(input).trim();

        // 1. Check for urgency and coercion
        for (String phrase : URGENCY) {
            if (text.contains(phrase)) {
                findings.add("Uses artificial urgency language: '" + phrase + "'");
                break;
            }
        }

        // 2. Check for requests for sensitive credentials
        for (String phrase : CREDENTIALS) {
            if (text.contains(phrase)) {
                findings.add("Asks for sensitive credentials/information: '" + phrase + "'");
                break;
            }
        }

        // 3. Check for prize or lottery claims
        for (String phrase : PRIZE) {
            if (text.contains(phrase)) {
                findings.add("Promises a prize, reward, or lottery: '" + phrase + "'");
                break;
            }
        }

        // 4. Check for coercive link-opening pressure
        for (String phrase : LINK_PRESSURE) {
            if (text.contains(phrase)) {
                findings.add("Pushes the reader to open a link: '" + phrase + "'");
                break;
            }
        }

        // 5. Check for suspicious financial / payment requests
        for (String phrase : PAYMENT_REQUESTS) {
            if (text.contains(phrase)) {
                findings.add("Suspicious financial or payment request: '" + phrase + "'");
                break;
            }
        }

        // 6. Check for embedded web links inside the message body
        if (text.contains("http://") || text.contains("https://") || text.contains("bit.ly") || text.contains("tinyurl.com")) {
            findings.add("Contains an embedded web link inside the message");
        }

        // 7. Check for generic impersonal greeting
        for (String phrase : GENERIC_GREETINGS) {
            if (text.contains(phrase)) {
                findings.add("Uses generic greeting instead of a personalized name: '" + phrase + "'");
                break;
            }
        }

        return findings;
    }

    /**
     * Standalone main method to demonstrate message detection.
     * Right-click inside this file and select: Run 'MessageDetector.main()'
     */
    public static void main(String[] args) {
        System.out.println("=== Testing MessageDetector (Tanisha - Cybersecurity Engine) ===\n");

        MessageDetector detector = new MessageDetector();

        String[] testMessages = {
                // Safe message
                "Hey Tanisha, are we meeting at the campus library at 4 PM for the project presentation?",

                // High-threat phishing message
                "Dear customer, your bank account is suspended immediately! Click here http://bit.ly/bank-fix to verify your password and OTP within 24 hours.",

                // Lottery / Reward scam message
                "Congratulations! You have won a $1,000,000 lottery cash reward! Claim now by sending your bank details.",

                // Payment fraud message
                "Security Alert: Unauthorized transaction detected. Wire transfer required to avoid account locked."
        };

        for (String msg : testMessages) {
            System.out.println("Message: \"" + msg + "\"");
            List<String> findings = detector.detect(msg);
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
