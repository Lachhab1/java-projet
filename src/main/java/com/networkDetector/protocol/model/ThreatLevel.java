package com.networkDetector.protocol.model;

public enum ThreatLevel {
    SAFE(0),
    LOW(1),
    MEDIUM(2),
    HIGH(3),
    CRITICAL(4);

    private final int level;

    ThreatLevel(int level) {
        this.level = level;
    }

    public int getLevel() {
        return level;
    }
}