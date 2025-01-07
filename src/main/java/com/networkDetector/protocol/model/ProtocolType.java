package com.networkDetector.protocol.model;

public enum ProtocolType {
    HTTPS(443),
    HTTP(80),
    FTP(21),
    DNS(53),
    SMTP(25),
    POP3(110),
    IMAP(143),
    SSH(22),
    TELNET(23),
    SNMP(161),
    RDP(3389),
    SFTP(22),
    LDAP(389),
    NTP(123),
    SNTP(123),
    DHCP(67),
    MQTT(1883),
    ICMP(1),
    ARP(0),
    SCTP(132),
    POP(110),

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