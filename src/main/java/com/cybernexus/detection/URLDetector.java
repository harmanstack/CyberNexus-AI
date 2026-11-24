package com.cybernexus.detection;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Rule-based URL checks used for Evaluation 1. These are defensive indicators only,
 * not an exploit or scanner against live systems.
 */
public class URLDetector extends AbstractDetector {
    private static final Pattern IP_HOST = Pattern.compile(
            "(?i)https?://(?:\\d{1,3}\\.){3}\\d{1,3}");
    private static final Pattern CREDENTIAL_IN_URL = Pattern.compile(
            "(?i)https?://[^/]*:[^/]*@");
    private static final String[] SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top"};
    private static final String[] SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly"};
    private static final String[] SENSITIVE_WORDS = {
            "login", "signin", "verify", "secure", "update", "account", "password", "billing"
    };
    private static final String[] BRAND_LOOKALIKES = {
            "paypa1", "paypai", "faceb00k", "micros0ft", "g00gle", "app1e-id", "netfIix"
    };

    @Override
    public String getType() {
        return "URL";
    }

    @Override
    public List<String> detect(String input) {
        List<String> findings = new ArrayList<>();
        String url = lower(input).trim();
        if (url.isEmpty()) {
            findings.add("Empty URL");
            return findings;
        }

        if (url.startsWith("http://")) {
            findings.add("Uses unencrypted HTTP instead of HTTPS");
        }
        if (IP_HOST.matcher(url).find()) {
            findings.add("Host is a raw IP address instead of a domain name");
        }
        if (url.contains("@") || CREDENTIAL_IN_URL.matcher(input).find()) {
            findings.add("URL contains '@' which can hide the real destination");
        }
        for (String tld : SUSPICIOUS_TLDS) {
            if (url.contains(tld)) {
                findings.add("Uses a frequently abused top-level domain: " + tld);
                break;
            }
        }
        for (String shortener : SHORTENERS) {
            if (url.contains(shortener)) {
                findings.add("URL shortener hides the final destination");
                break;
            }
        }
        int hyphens = countChar(url, '-');
        if (hyphens >= 4) {
            findings.add("Unusually many hyphens in the URL");
        }
        for (String word : SENSITIVE_WORDS) {
            if (containsIgnoreCase(url, word)) {
                findings.add("Contains sensitive keyword: " + word);
                break;
            }
        }
        for (String lookalike : BRAND_LOOKALIKES) {
            if (containsIgnoreCase(url, lookalike)) {
                findings.add("Possible brand impersonation: " + lookalike);
                break;
            }
        }
        if (url.length() > 120) {
            findings.add("URL is unusually long");
        }
        return findings;
    }

    private int countChar(String text, char target) {
        int count = 0;
        for (int i = 0; i < text.length(); i++) {
            if (text.charAt(i) == target) {
                count++;
            }
        }
        return count;
    }
}
