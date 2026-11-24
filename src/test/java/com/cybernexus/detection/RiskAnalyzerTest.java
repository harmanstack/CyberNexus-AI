package com.cybernexus.detection;

import com.cybernexus.model.ScanResult;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RiskAnalyzerTest {
    private final RiskAnalyzer analyzer = new RiskAnalyzer();

    @Test
    void highWhenManyStrongIndicators() {
        ScanResult result = analyzer.analyze("URL", "http://paypa1.xyz", List.of(
                "Possible brand impersonation: paypa1",
                "Uses a frequently abused top-level domain: .xyz",
                "URL contains '@' which can hide the real destination"));
        assertEquals("HIGH", result.getRiskLevel());
        assertTrue(result.getRiskScore() > 70);
    }

    @Test
    void lowWhenNoFindings() {
        ScanResult result = analyzer.analyze("URL", "https://example.com", List.of());
        assertEquals("LOW", result.getRiskLevel());
    }

    @Test
    void clampKeepsRange() {
        assertEquals(0, analyzer.clamp(-4));
        assertEquals(100, analyzer.clamp(140));
    }
}
