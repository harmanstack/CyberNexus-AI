package com.cybernexus.service;

import com.cybernexus.dao.ScanDAO;
import com.cybernexus.detection.Detector;
import com.cybernexus.detection.MessageDetector;
import com.cybernexus.detection.RiskAnalyzer;
import com.cybernexus.detection.URLDetector;
import com.cybernexus.model.Scan;
import com.cybernexus.model.ScanResult;
import com.cybernexus.model.User;
import com.cybernexus.util.InputValidator;

import java.sql.SQLException;
import java.util.List;

/** Runs detectors, scores the result, optionally explains it, and stores history. */
public class ScanService {
    private final ScanDAO scanDAO;
    private final Detector urlDetector;
    private final Detector messageDetector;
    private final RiskAnalyzer riskAnalyzer;
    private final AIService aiService;

    public ScanService() {
        this(new ScanDAO(), new URLDetector(), new MessageDetector(),
                new RiskAnalyzer(), new AIService());
    }

    public ScanService(ScanDAO scanDAO, Detector urlDetector, Detector messageDetector,
                       RiskAnalyzer riskAnalyzer, AIService aiService) {
        this.scanDAO = scanDAO;
        this.urlDetector = urlDetector;
        this.messageDetector = messageDetector;
        this.riskAnalyzer = riskAnalyzer;
        this.aiService = aiService;
    }

    public ScanResult scanUrl(User user, String rawUrl) throws SQLException {
        String url = InputValidator.requireUrl(rawUrl);
        return runScan(user, urlDetector, url);
    }

    public ScanResult scanMessage(User user, String rawMessage) throws SQLException {
        String message = InputValidator.requireText(rawMessage, "Message");
        return runScan(user, messageDetector, message);
    }

    public ScanResult explainOnly(String scanType, String input) {
        Detector detector = "MESSAGE".equalsIgnoreCase(scanType) ? messageDetector : urlDetector;
        ScanResult result = riskAnalyzer.analyze(detector.getType(), input, detector.detect(input));
        result.setExplanation(aiService.explain(result));
        return result;
    }

    public List<Scan> historyFor(User user) throws SQLException {
        return scanDAO.findByUserId(user.getId());
    }

    private ScanResult runScan(User user, Detector detector, String input) throws SQLException {
        ScanResult result = riskAnalyzer.analyze(detector.getType(), input, detector.detect(input));
        result.setExplanation(aiService.explain(result));
        Scan scan = new Scan(
                user.getId(),
                result.getScanType(),
                result.getInputData(),
                result.getRiskScore(),
                result.getRiskLevel(),
                result.joinedReasons());
        scanDAO.saveScan(scan);
        return result;
    }
}
