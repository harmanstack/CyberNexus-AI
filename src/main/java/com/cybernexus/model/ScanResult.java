package com.cybernexus.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** In-memory result of a scan before it is saved to MySQL. */
public class ScanResult {
    private final String scanType;
    private final String inputData;
    private final int riskScore;
    private final String riskLevel;
    private final List<String> reasons;
    private String explanation;

    public ScanResult(String scanType, String inputData, int riskScore,
                      String riskLevel, List<String> reasons) {
        this.scanType = scanType;
        this.inputData = inputData;
        this.riskScore = riskScore;
        this.riskLevel = riskLevel;
        this.reasons = new ArrayList<>(reasons);
    }

    public String getScanType() {
        return scanType;
    }

    public String getInputData() {
        return inputData;
    }

    public int getRiskScore() {
        return riskScore;
    }

    public String getRiskLevel() {
        return riskLevel;
    }

    public List<String> getReasons() {
        return Collections.unmodifiableList(reasons);
    }

    public String joinedReasons() {
        if (reasons.isEmpty()) {
            return "No matching threat indicators.";
        }
        return String.join(" | ", reasons);
    }

    public String getExplanation() {
        return explanation;
    }

    public void setExplanation(String explanation) {
        this.explanation = explanation;
    }
}
