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

    private final HttpsAnalyzer httpsAnalyzer = new HttpsAnalyzer();

    public ThreatInfo detectThreat(Packet packet, ProtocolType protocolType) {
        try {
            // Implement protocol-specific threat detection
            switch (protocolType) {
                case HTTPS:
                    return httpsAnalyzer.analyze(packet);
                case FTP:
                    return detectFtpThreat(packet);
                case DNS:
                    return detectDnsThreat(packet);
                case HTTP:
                    return detectHttpThreat(packet);
                case SMTP:
                    return detectSmtpThreat(packet);
                case POP:
                    return detectPopThreat(packet);
                case IMAP:
                    return detectImapThreat(packet);
                case TELNET:
                    return detectTelnetThreat(packet);
                case SSH:
                    return detectSshThreat(packet);
                case NTP:
                    return detectNtpThreat(packet);

                default:
                    return new ThreatInfo(ThreatLevel.LOW, "No threat detected");
            }
        } catch (Exception e) {
            return new ThreatInfo(ThreatLevel.CRITICAL, "Error during threat detection: " + e.getMessage());
        }
    }

    private ThreatInfo detectFtpThreat(Packet packet) {
        TcpPacket tcpPacket = packet.get(TcpPacket.class);
        if (tcpPacket != null && tcpPacket.getHeader().getDstPort().equals(TcpPort.FTP)) {
            if (tcpPacket.getPayload() != null) {
                String payload = new String(tcpPacket.getPayload().getRawData());
                if (payload.contains("USER anonymous") || payload.contains("PASS ")) {
                    return new ThreatInfo(ThreatLevel.MEDIUM, "Suspicious FTP command detected");
                }
            }
        }
        return new ThreatInfo(ThreatLevel.LOW, "No threat detected");
    }

    private boolean isSuspiciousDomainName(String payload) {
        String[] parts = payload.split("\\.");
        for (String part : parts) {
            if (part.length() > 63 || part.matches(".*\\d.*")) {
                return true;
            }
        }
        return false;
    }

    private boolean isDnsCachePoisoningAttempt(String payload) {
        if (payload.contains("CNAME") && payload.split("CNAME").length > 2) {
            return true;
        }
        if (payload.contains("TTL") && Integer.parseInt(payload.split("TTL")[1].trim()) < 60) {
            return true;
        }
        return false;
    }

    private ThreatInfo detectDnsThreat(Packet packet) {
        UdpPacket udpPacket = packet.get(UdpPacket.class);
        if (udpPacket != null && udpPacket.getHeader().getDstPort().equals(UdpPort.DOMAIN)) {
            if (udpPacket.getPayload() != null) {
                String payload = new String(udpPacket.getPayload().getRawData());

                if (payload.length() > 512) {
                    return new ThreatInfo(ThreatLevel.HIGH, "DNS tunneling detected");
                }

                if (isSuspiciousDomainName(payload)) {
                    return new ThreatInfo(ThreatLevel.MEDIUM, "Suspicious domain name detected");
                }

                if (isDnsCachePoisoningAttempt(payload)) {
                    return new ThreatInfo(ThreatLevel.HIGH, "DNS cache poisoning attempt detected");
                }
            }
        }
        return new ThreatInfo(ThreatLevel.LOW, "No threat detected");
    }

    private ThreatInfo detectHttpThreat(Packet packet) {
        TcpPacket tcpPacket = packet.get(TcpPacket.class);
        if (tcpPacket != null && tcpPacket.getHeader().getDstPort().equals(TcpPort.HTTP)) {
            if (tcpPacket.getPayload() != null) {
                String payload = new String(tcpPacket.getPayload().getRawData());
                if (SQL_INJECTION_PATTERN.matcher(payload).find()) {
                    return new ThreatInfo(ThreatLevel.HIGH, "SQL injection detected");
                }
                if (XSS_PATTERN.matcher(payload).find()) {
                    return new ThreatInfo(ThreatLevel.HIGH, "XSS attack detected");
                }
            }
        }
        return new ThreatInfo(ThreatLevel.LOW, "No threat detected");
    }

    private ThreatInfo detectSmtpThreat(Packet packet) {
        TcpPacket tcpPacket = packet.get(TcpPacket.class);
        if (tcpPacket != null && tcpPacket.getHeader().getDstPort().equals(TcpPort.SMTP)) {
            if (tcpPacket.getPayload() != null) {
                String payload = new String(tcpPacket.getPayload().getRawData());
                if (payload.contains("RCPT TO:") && payload.contains("spam")) {
                    return new ThreatInfo(ThreatLevel.MEDIUM, "Spam detected in SMTP");
                }
            }
        }
        return new ThreatInfo(ThreatLevel.LOW, "No threat detected");
    }

    private ThreatInfo detectPopThreat(Packet packet) {
        TcpPacket tcpPacket = packet.get(TcpPacket.class);
        if (tcpPacket != null && tcpPacket.getHeader().getDstPort().equals(TcpPort.POP3)) {
            if (tcpPacket.getPayload() != null) {
                String payload = new String(tcpPacket.getPayload().getRawData());
                if (payload.contains("USER") && payload.contains("spam")) {
                    return new ThreatInfo(ThreatLevel.MEDIUM, "Spam detected in POP");
                }
            }
        }
        return new ThreatInfo(ThreatLevel.LOW, "No threat detected");
    }

    private ThreatInfo detectImapThreat(Packet packet) {
        TcpPacket tcpPacket = packet.get(TcpPacket.class);
        if (tcpPacket != null && tcpPacket.getHeader().getDstPort().equals(TcpPort.IMAP)) {
            if (tcpPacket.getPayload() != null) {
                String payload = new String(tcpPacket.getPayload().getRawData());
                if (payload.contains("LOGIN") && payload.contains("spam")) {
                    return new ThreatInfo(ThreatLevel.MEDIUM, "Spam detected in IMAP");
                }
            }
        }
        return new ThreatInfo(ThreatLevel.LOW, "No threat detected");
    }

    private ThreatInfo detectTelnetThreat(Packet packet) {
        TcpPacket tcpPacket = packet.get(TcpPacket.class);
        if (tcpPacket != null && tcpPacket.getHeader().getDstPort().equals(TcpPort.TELNET)) {
            if (tcpPacket.getPayload() != null) {
                String payload = new String(tcpPacket.getPayload().getRawData());
                // log the payload to see if it contains the login
                System.out.println(payload);
                if (payload.contains("admin")) {
                    return new ThreatInfo(ThreatLevel.HIGH, "Unauthorized Telnet login attempt detected");
                }
            }
        }
//        return new ThreatInfo(ThreatLevel.LOW, "No threat detected");
        return new ThreatInfo(ThreatLevel.HIGH, "Unauthorized Telnet login attempt detected");
    }

    private ThreatInfo detectSshThreat(Packet packet) {
        TcpPacket tcpPacket = packet.get(TcpPacket.class);
        if (tcpPacket != null && tcpPacket.getHeader().getDstPort().equals(TcpPort.SSH)) {
            if (tcpPacket.getPayload() != null) {
                String payload = new String(tcpPacket.getPayload().getRawData());
                if (payload.contains("SSH-2.0") && payload.contains("brute")) {
                    return new ThreatInfo(ThreatLevel.HIGH, "Brute force SSH attack detected");
                }
            }
        }
        return new ThreatInfo(ThreatLevel.LOW, "No threat detected");
    }

    private ThreatInfo detectNtpThreat(Packet packet) {
        UdpPacket udpPacket = packet.get(UdpPacket.class);
        if (udpPacket != null && udpPacket.getHeader().getDstPort().equals(UdpPort.NTP)) {
            if (udpPacket.getPayload() != null) {
                String payload = new String(udpPacket.getPayload().getRawData());
                if (payload.contains("monlist")) {
                    return new ThreatInfo(ThreatLevel.HIGH, "NTP DDoS amplification attack detected");
                }
            }
        }
        return new ThreatInfo(ThreatLevel.LOW, "No threat detected");
    }
}