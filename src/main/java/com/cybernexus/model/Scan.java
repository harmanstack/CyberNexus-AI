package com.cybernexus.model;

import java.time.LocalDateTime;

/** One saved URL or message scan row from MySQL. */
public class Scan {
    private int id;
    private int userId;
    private String scanType;
    private String inputData;
    private int riskScore;
    private String riskLevel;
    private String detectionReason;
    private LocalDateTime createdAt;

    public Scan() {
    }

    public Scan(int userId, String scanType, String inputData, int riskScore,
                String riskLevel, String detectionReason) {
        this.userId = userId;
        this.scanType = scanType;
        this.inputData = inputData;
        this.riskScore = riskScore;
        this.riskLevel = riskLevel;
        this.detectionReason = detectionReason;
    }

    public Scan(int id, int userId, String scanType, String inputData, int riskScore,
                String riskLevel, String detectionReason, LocalDateTime createdAt) {
        this.id = id;
        this.userId = userId;
        this.scanType = scanType;
        this.inputData = inputData;
        this.riskScore = riskScore;
        this.riskLevel = riskLevel;
        this.detectionReason = detectionReason;
        this.createdAt = createdAt;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public int getUserId() {
        return userId;
    }

    public void setUserId(int userId) {
        this.userId = userId;
    }

    public String getScanType() {
        return scanType;
    }

    public void setScanType(String scanType) {
        this.scanType = scanType;
    }

    public String getInputData() {
        return inputData;
    }

    public void setInputData(String inputData) {
        this.inputData = inputData;
    }

    public int getRiskScore() {
        return riskScore;
    }

    public void setRiskScore(int riskScore) {
        this.riskScore = riskScore;
    }

    public String getRiskLevel() {
        return riskLevel;
    }

    public void setRiskLevel(String riskLevel) {
        this.riskLevel = riskLevel;
    }

    public String getDetectionReason() {
        return detectionReason;
    }

    public void setDetectionReason(String detectionReason) {
        this.detectionReason = detectionReason;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }
}
