package com.cybernexus.service;

import com.cybernexus.config.DBConnection;
import com.cybernexus.model.ScanResult;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Builds a threat explanation. Tries an optional HTTP API first, then a local
 * template so the app still works when the API is missing (Evaluation 2).
 */
public class AIService {
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(3))
            .build();

    public String explain(ScanResult result) {
        String remote = tryRemoteExplanation(result);
        if (remote != null && !remote.isBlank()) {
            return remote;
        }
        return localExplanation(result);
    }

    private String tryRemoteExplanation(ScanResult result) {
        String endpoint;
        try {
            endpoint = DBConnection.getAiApiUrl();
        } catch (RuntimeException ignored) {
            return null;
        }
        if (endpoint == null || endpoint.isBlank()) {
            return null;
        }
        try {
            String body = "{\"type\":\"" + result.getScanType()
                    + "\",\"score\":" + result.getRiskScore() + "}";
            HttpRequest request = HttpRequest.newBuilder(URI.create(endpoint))
                    .timeout(Duration.ofSeconds(4))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() >= 200 && response.statusCode() < 300
                    && response.body() != null && !response.body().isBlank()) {
                return "AI API: " + response.body();
            }
        } catch (Exception ignored) {
            // Fall back to the local explanation so a down API does not crash the menu.
        }
        return null;
    }

    public String localExplanation(ScanResult result) {
        StringBuilder text = new StringBuilder();
        text.append("This ").append(result.getScanType().toLowerCase())
                .append(" was rated ").append(result.getRiskLevel())
                .append(" (").append(result.getRiskScore()).append("/100). ");
        if (result.getReasons().isEmpty() || result.getRiskScore() <= 30) {
            text.append("No strong phishing indicators were found. Still avoid sharing passwords or OTPs.");
        } else {
            text.append("Why: ").append(result.joinedReasons()).append(". ");
            text.append(recommendationFor(result.getRiskLevel()));
        }
        return text.toString();
    }

    public String recommendationFor(String level) {
        if ("HIGH".equals(level)) {
            return "Do not open the link or reply. Report it and use the official website or app instead.";
        }
        if ("MEDIUM".equals(level)) {
            return "Treat it as suspicious. Confirm the sender through another channel before taking action.";
        }
        return "Low risk, but stay cautious with unexpected requests.";
    }
}
