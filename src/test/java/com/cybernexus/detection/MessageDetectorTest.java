package com.cybernexus.detection;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MessageDetectorTest {
    private final MessageDetector detector = new MessageDetector();

    @Test
    void flagsUrgencyAndPasswordRequest() {
        List<String> findings = detector.detect(
                "Urgent: your account will be closed. Send your password now.");
        assertFalse(findings.isEmpty());
        assertTrue(findings.stream().anyMatch(item -> item.toLowerCase().contains("urgency")
                || item.toLowerCase().contains("sensitive")));
    }
}
