package com.networkDetector.protocol.analyzer;

import com.networkDetector.protocol.model.ProtocolData;
import com.networkDetector.protocol.model.ThreatInfo;
import com.networkDetector.protocol.model.ThreatLevel;
import com.networkDetector.protocol.model.ProtocolType;
import com.networkDetector.logging.NetworkLogger;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

import java.time.LocalDateTime;

public class ProtocolAnalyzer {
    private final ThreatDetector threatDetector;
    private final NetworkLogger networkLogger;

    public ProtocolAnalyzer(NetworkLogger networkLogger) {
        this.networkLogger = networkLogger;
        this.threatDetector = new ThreatDetector();
    }

    public ProtocolData analyzePacket(Packet packet) {
        IpPacket ipPacket = packet.get(IpPacket.class);
        if (ipPacket == null) {
            return null;
        }

        String sourceAddr = ipPacket.getHeader().getSrcAddr().getHostAddress();
        String destAddr = ipPacket.getHeader().getDstAddr().getHostAddress();

        TcpPacket tcpPacket = packet.get(TcpPacket.class);
        if (tcpPacket != null) {
            return analyzeTcpPacket(tcpPacket, ipPacket, sourceAddr, destAddr);
        }

        UdpPacket udpPacket = packet.get(UdpPacket.class);
        if (udpPacket != null) {
            return analyzeUdpPacket(udpPacket, ipPacket, sourceAddr, destAddr);
        }

        return null;
    }

    private ProtocolData analyzeTcpPacket(TcpPacket tcpPacket, IpPacket ipPacket, String sourceAddr, String destAddr) {
        int dstPort = tcpPacket.getHeader().getDstPort().valueAsInt();
        ProtocolType protocolType = ProtocolType.fromPort(dstPort);
        ThreatInfo threatInfo = threatDetector.detectThreat(tcpPacket, protocolType);
        ThreatLevel threatLevel = threatInfo.getThreatLevel();
        String threatType = threatInfo.getThreatType();

        String analysis = String.format("TCP packet analysis: Protocol: %s, Threat Type: %s, Threat Level: %s",
                protocolType, threatType, threatLevel);

        if (threatLevel != ThreatLevel.LOW) {
            networkLogger.logSecurityEvent(String.format(
                    "Potential threat detected - Protocol: %s, Source: %s, Threat Level: %s",
                    protocolType, sourceAddr, threatLevel));
        }

        return new ProtocolData.Builder()
                .protocolType(protocolType)
                .sourceAddress(sourceAddr)
                .destinationAddress(destAddr)
                .sourcePort(tcpPacket.getHeader().getSrcPort().valueAsInt())
                .destinationPort(dstPort)
                .timestamp(LocalDateTime.now())
                .threatLevel(threatLevel)
                .analysis(analysis)
                .build();
    }

    private ProtocolData analyzeUdpPacket(UdpPacket udpPacket, IpPacket ipPacket, String sourceAddr, String destAddr) {
        int dstPort = udpPacket.getHeader().getDstPort().valueAsInt();
        ProtocolType protocolType = ProtocolType.fromPort(dstPort);
        ThreatInfo threatInfo = threatDetector.detectThreat(udpPacket, protocolType);
        ThreatLevel threatLevel = threatInfo.getThreatLevel();
        String threatType = threatInfo.getThreatType();

        String analysis = String.format("UDP packet analysis: Protocol: %s, Threat Type: %s, Threat Level: %s",
                protocolType, threatType, threatLevel);

        if (threatLevel != ThreatLevel.LOW) {
            networkLogger.logSecurityEvent(String.format(
                    "Potential threat detected - Protocol: %s, Source: %s, Threat Level: %s",
                    protocolType, sourceAddr, threatLevel));
        }

        return new ProtocolData.Builder()
                .protocolType(protocolType)
                .sourceAddress(sourceAddr)
                .destinationAddress(destAddr)
                .sourcePort(udpPacket.getHeader().getSrcPort().valueAsInt())
                .destinationPort(dstPort)
                .timestamp(LocalDateTime.now())
                .threatLevel(threatLevel)
                .analysis(analysis)
                .build();
    }
}