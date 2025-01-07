package com.networkDetector.protocol.model;

public class ThreatInfo {
    private final ThreatLevel threatLevel;
    private final String threatType;

    public ThreatInfo(ThreatLevel threatLevel, String threatType) {
        this.threatLevel = threatLevel;
        this.threatType = threatType;
    }

    public ThreatLevel getThreatLevel() {
        return threatLevel;
    }

    public String getThreatType() {
        return threatType;
    }
}