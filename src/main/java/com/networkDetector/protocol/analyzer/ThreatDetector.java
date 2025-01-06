package com.networkDetector.protocol.analyzer;

import com.networkDetector.protocol.model.*;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.namednumber.TcpPort;
import org.pcap4j.packet.namednumber.UdpPort;

import java.util.regex.Pattern;

public class ThreatDetector {
    private static final Pattern SQL_INJECTION_PATTERN = Pattern.compile(
            "(?i)(\\b(select|insert|update|delete|drop|union|exec)\\b)");
    private static final Pattern XSS_PATTERN = Pattern.compile(
            "(?i)(<script|javascript:|on\\w+\\s*=)");

    public ThreatLevel detectThreat(Packet packet, ProtocolType protocolType) {
        try {
            // Implement protocol-specific threat detection
            switch (protocolType) {
                case HTTPS:
                    return detectHttpsThreat(packet);
                case FTP:
                    return detectFtpThreat(packet);
                case DNS:
                    return detectDnsThreat(packet);
                default:
                    return ThreatLevel.LOW;
            }
        } catch (Exception e) {
            return ThreatLevel.MEDIUM; // Default to medium on error
        }
    }

    private ThreatLevel detectHttpsThreat(Packet packet) {
        // Implement HTTPS-specific threat detection
        // Check for certificate validity, known malicious patterns, etc.
        TcpPacket tcpPacket = packet.get(TcpPacket.class);
        if (tcpPacket != null && tcpPacket.getHeader().getDstPort().equals(TcpPort.HTTPS)) {
            // Example: Check for SQL injection in HTTPS payload
            String payload = new String(tcpPacket.getPayload().getRawData());
            if (SQL_INJECTION_PATTERN.matcher(payload).find()) {
                return ThreatLevel.HIGH;
            }
        }
        return ThreatLevel.LOW;
    }

    private ThreatLevel detectFtpThreat(Packet packet) {
        // Implement FTP-specific threat detection
        // Check for unauthorized access attempts, suspicious commands, etc.
        TcpPacket tcpPacket = packet.get(TcpPacket.class);
        if (tcpPacket != null && tcpPacket.getHeader().getDstPort().equals(TcpPort.FTP)) {
            // Example: Check for suspicious FTP commands
            String payload = new String(tcpPacket.getPayload().getRawData());
            if (payload.contains("USER anonymous") || payload.contains("PASS ")) {
                return ThreatLevel.MEDIUM;
            }
        }
        return ThreatLevel.LOW;
    }

    private ThreatLevel detectDnsThreat(Packet packet) {
        // Implement DNS-specific threat detection
        // Check for DNS tunneling, cache poisoning attempts, etc.
        UdpPacket udpPacket = packet.get(UdpPacket.class);
        if (udpPacket != null && udpPacket.getHeader().getDstPort().equals(UdpPort.DOMAIN)) {
            // Example: Check for DNS tunneling patterns
            String payload = new String(udpPacket.getPayload().getRawData());
            if (payload.length() > 512) { // DNS packets should not exceed 512 bytes
                return ThreatLevel.HIGH;
            }
        }
        return ThreatLevel.LOW;
    }
}