package com.networkDetector.protocol.model;

public enum ProtocolType {
    HTTPS(443),
    HTTP(80),
    FTP(21),
    DNS(53),
    UNKNOWN(-1);

    private final int defaultPort;

    ProtocolType(int defaultPort) {
        this.defaultPort = defaultPort;
    }

    public int getDefaultPort() {
        return defaultPort;
    }

    public static ProtocolType fromPort(int port) {
        for (ProtocolType type : values()) {
            if (type.getDefaultPort() == port) {
                return type;
            }
        }
        return UNKNOWN;
    }
}