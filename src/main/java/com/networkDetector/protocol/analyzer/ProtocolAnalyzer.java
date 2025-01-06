package com.networkDetector.protocol.analyzer;

import com.networkDetector.logging.NetworkLogger;
import com.networkDetector.protocol.model.*;
import org.pcap4j.packet.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

public class ProtocolAnalyzer {
    private static final Logger logger = LoggerFactory.getLogger(ProtocolAnalyzer.class);
    private final NetworkLogger networkLogger;
    private final ConcurrentHashMap<String, AtomicInteger> connectionCounter;
    private final ThreatDetector threatDetector;

    public ProtocolAnalyzer(NetworkLogger networkLogger) {
        this.networkLogger = networkLogger;
        this.connectionCounter = new ConcurrentHashMap<>();
        this.threatDetector = new ThreatDetector();
    }

    public ProtocolData analyzePacket(Packet packet) {
        try {
            IpPacket ipPacket = packet.get(IpPacket.class);
            if (ipPacket == null) {
                return null;
            }

            TcpPacket tcpPacket = packet.get(TcpPacket.class);
            if (tcpPacket != null) {
                return analyzeTcpPacket(tcpPacket, ipPacket);
            }

            UdpPacket udpPacket = packet.get(UdpPacket.class);
            if (udpPacket != null) {
                return analyzeUdpPacket(udpPacket, ipPacket);
            }

            return null;
        } catch (Exception e) {
            logger.error("Error analyzing packet: {}", e.getMessage());
            return null;
        }
    }

    private ProtocolData analyzeTcpPacket(TcpPacket tcpPacket, IpPacket ipPacket) {
        int dstPort = tcpPacket.getHeader().getDstPort().valueAsInt();
        ProtocolType protocolType = ProtocolType.fromPort(dstPort);

        String sourceAddr = ipPacket.getHeader().getSrcAddr().getHostAddress();
        String destAddr = ipPacket.getHeader().getDstAddr().getHostAddress();

        // Track connection attempts
        String connectionKey = sourceAddr + ":" + destAddr;
        connectionCounter.computeIfAbsent(connectionKey, k -> new AtomicInteger(0))
                .incrementAndGet();

        // Analyze threat level
        ThreatLevel threatLevel = threatDetector.detectThreat(tcpPacket, protocolType);

        if (threatLevel.getLevel() >= ThreatLevel.MEDIUM.getLevel()) {
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
                .analysis("TCP packet analysis")
                .build();
    }

    private ProtocolData analyzeUdpPacket(UdpPacket udpPacket, IpPacket ipPacket) {
        // Similar implementation for UDP packets
        // Particularly important for DNS analysis
        // ... (implement UDP analysis)
        return null;
    }
}