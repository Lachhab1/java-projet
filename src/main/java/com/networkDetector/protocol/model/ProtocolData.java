package com.networkDetector.protocol.model;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;

public class ProtocolData {
    private static final Logger log = LoggerFactory.getLogger(ProtocolData.class);
    private final ProtocolType protocolType;
    private final String sourceAddress;
    private final String destinationAddress;
    private final int sourcePort;
    private final int destinationPort;
    private final LocalDateTime timestamp;
    private final ThreatLevel threatLevel;
    private final String analysis;

    private ProtocolData(Builder builder) {
        this.protocolType = builder.protocolType;
        this.sourceAddress = builder.sourceAddress;
        this.destinationAddress = builder.destinationAddress;
        this.sourcePort = builder.sourcePort;
        this.destinationPort = builder.destinationPort;
        this.timestamp = builder.timestamp;
        this.threatLevel = builder.threatLevel;
        this.analysis = builder.analysis;
    }

    public static class Builder {
        private ProtocolType protocolType;
        private String sourceAddress;
        private String destinationAddress;
        private int sourcePort;
        private int destinationPort;
        private LocalDateTime timestamp;
        private ThreatLevel threatLevel;
        private String analysis;

        public Builder protocolType(ProtocolType protocolType) {
            this.protocolType = protocolType;
            return this;
        }

        public Builder sourceAddress(String sourceAddress) {
            this.sourceAddress = sourceAddress;
            return this;
        }

        public Builder destinationAddress(String destinationAddress) {
            this.destinationAddress = destinationAddress;
            return this;
        }

        public Builder sourcePort(int sourcePort) {
            this.sourcePort = sourcePort;
            return this;
        }

        public Builder destinationPort(int destinationPort) {
            this.destinationPort = destinationPort;
            return this;
        }

        public Builder timestamp(LocalDateTime timestamp) {
            this.timestamp = timestamp;
            return this;
        }

        public Builder threatLevel(ThreatLevel threatLevel) {
            this.threatLevel = threatLevel;
            return this;
        }

        public Builder analysis(String analysis) {
            this.analysis = analysis;
            return this;
        }

        public ProtocolData build() {
            return new ProtocolData(this);
        }
    }

    // Getters
    public ProtocolType getProtocolType() {
        return protocolType;
    }

    public String getSourceAddress() {
        return sourceAddress;
    }

    public String getDestinationAddress() {
        return destinationAddress;
    }

    public int getSourcePort() {
        return sourcePort;
    }

    public int getDestinationPort() {
        return destinationPort;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public ThreatLevel getThreatLevel() {
        return threatLevel;
    }

    public String getAnalysis() {
        return analysis;
    }

    @Override
    public String toString() {
        return "ProtocolData{" +
                "protocolType=" + protocolType +
                ", sourceAddress='" + sourceAddress + '\'' +
                ", destinationAddress='" + destinationAddress + '\'' +
                ", sourcePort=" + sourcePort +
                ", destinationPort=" + destinationPort +
                ", timestamp=" + timestamp +
                ", threatLevel=" + threatLevel +
                ", analysis='" + analysis + '\'' +
                '}';
    }
}