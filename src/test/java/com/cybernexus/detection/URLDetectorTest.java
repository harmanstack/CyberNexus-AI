package com.cybernexus.detection;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class URLDetectorTest {
    private final URLDetector detector = new URLDetector();

    @Test
    void flagsHttpAndLoginKeyword() {
        List<String> findings = detector.detect("http://secure-login.example.xyz/account");
        assertFalse(findings.isEmpty());
        assertTrue(findings.stream().anyMatch(item -> item.toLowerCase().contains("http")));
    }

    @Test
    void quietOnSimpleHttpsSite() {
        List<String> findings = detector.detect("https://university.edu/news");
        assertTrue(findings.isEmpty());
    }
}
