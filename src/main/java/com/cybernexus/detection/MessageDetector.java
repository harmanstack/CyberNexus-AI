package com.cybernexus.detection;

import java.util.ArrayList;
import java.util.List;

/** Rule-based phishing-message checks for Evaluation 1. */
public class MessageDetector extends AbstractDetector {
    private static final String[] URGENCY = {
            "urgent", "immediately", "act now", "within 24 hours", "account will be closed",
            "suspended", "last chance"
    };
    private static final String[] CREDENTIALS = {
            "password", "otp", "one-time", "pin", "ssn", "social security", "cvv", "bank details"
    };
    private static final String[] PRIZE = {
            "you have won", "lottery", "prize", "free gift", "claim now"
    };
    private static final String[] LINK_PRESSURE = {
            "click here", "click the link", "open this link", "verify here"
    };

    @Override
    public String getType() {
        return "MESSAGE";
    }

    @Override
    public List<String> detect(String input) {
        List<String> findings = new ArrayList<>();
        String text = lower(input);
        if (text.isBlank()) {
            findings.add("Empty message");
            return findings;
        }

        for (String phrase : URGENCY) {
            if (text.contains(phrase)) {
                findings.add("Uses urgency language: " + phrase);
                break;
            }
        }
        for (String phrase : CREDENTIALS) {
            if (text.contains(phrase)) {
                findings.add("Asks for sensitive information: " + phrase);
                break;
            }
        }
        for (String phrase : PRIZE) {
            if (text.contains(phrase)) {
                findings.add("Promises a prize or lottery: " + phrase);
                break;
            }
        }
        for (String phrase : LINK_PRESSURE) {
            if (text.contains(phrase)) {
                findings.add("Pushes the reader to open a link: " + phrase);
                break;
            }
        }
        if (text.contains("http://") || text.contains("https://") || text.contains("bit.ly")) {
            findings.add("Contains a web link inside the message");
        }
        if (text.contains("dear customer") || text.contains("dear user")) {
            findings.add("Generic greeting instead of a real name");
        }
        return findings;
    }
}
