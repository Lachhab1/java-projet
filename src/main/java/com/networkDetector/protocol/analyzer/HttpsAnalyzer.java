package com.networkDetector.protocol.analyzer;

import com.networkDetector.protocol.model.ThreatInfo;
import com.networkDetector.protocol.model.ThreatLevel;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.namednumber.TcpPort;

import java.util.regex.Pattern;

public class HttpsAnalyzer {
    private static final Pattern SQL_INJECTION_PATTERN = Pattern.compile(
            "(?i)(\\b(select|insert|update|delete|drop|union|exec)\\b)");
    private static final Pattern XSS_PATTERN = Pattern.compile(
            "(?i)(<script|javascript:|on\\w+\\s*=)");

    public ThreatInfo analyze(Packet packet) {
        TcpPacket tcpPacket = packet.get(TcpPacket.class);
        if (tcpPacket != null && tcpPacket.getHeader().getDstPort().equals(TcpPort.HTTPS)) {
            if (tcpPacket.getPayload() != null && tcpPacket.getPayload().getRawData() != null) {
                String payload = new String(tcpPacket.getPayload().getRawData());

                // Check for SQL injection patterns
                if (SQL_INJECTION_PATTERN.matcher(payload).find()) {
                    return new ThreatInfo(ThreatLevel.HIGH, "SQL injection detected");
                }

                // Check for XSS patterns
                if (XSS_PATTERN.matcher(payload).find()) {
                    return new ThreatInfo(ThreatLevel.HIGH, "XSS attack detected");
                }

                // Additional HTTPS-specific checks can be added here
                // For example, checking for certificate validity, known malicious patterns,
                // etc.
            }
        }
        return new ThreatInfo(ThreatLevel.LOW, "No threat detected");
    }
}