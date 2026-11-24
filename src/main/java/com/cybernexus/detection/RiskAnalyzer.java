package com.cybernexus.detection;

import com.cybernexus.model.ScanResult;

import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Turns detector findings into a 0-100 score and LOW / MEDIUM / HIGH level.
 */
public class RiskAnalyzer {
    private final Map<String, Integer> keywordWeights = new HashMap<>();

    public RiskAnalyzer() {
        keywordWeights.put("http instead", 15);
        keywordWeights.put("ip address", 25);
        keywordWeights.put("@", 30);
        keywordWeights.put("top-level domain", 20);
        keywordWeights.put("shortener", 25);
        keywordWeights.put("hyphens", 10);
        keywordWeights.put("sensitive keyword", 20);
        keywordWeights.put("impersonation", 35);
        keywordWeights.put("unusually long", 10);
        keywordWeights.put("empty", 5);
        keywordWeights.put("urgency", 15);
        keywordWeights.put("sensitive information", 30);
        keywordWeights.put("prize", 20);
        keywordWeights.put("open a link", 15);
        keywordWeights.put("web link", 10);
        keywordWeights.put("generic greeting", 10);
    }

    public ScanResult analyze(String scanType, String input, List<String> reasons) {
        int score = 0;
        for (String reason : reasons) {
            score += weightFor(reason);
        }
        if (reasons.isEmpty()) {
            score = 5;
        }
        score = clamp(score);
        return new ScanResult(scanType, input, score, levelForScore(score), reasons);
    }

    public String levelForScore(int score) {
        if (score <= 30) {
            return "LOW";
        }
        if (score <= 70) {
            return "MEDIUM";
        }
        return "HIGH";
    }

    public int clamp(int score) {
        return Math.max(0, Math.min(100, score));
    }

    private int weightFor(String reason) {
        String lowered = reason.toLowerCase(Locale.ROOT);
        for (Map.Entry<String, Integer> entry : keywordWeights.entrySet()) {
            if (lowered.contains(entry.getKey())) {
                return entry.getValue();
            }
        }
        return 12;
    }
}
