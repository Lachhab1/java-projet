package com.networkDetector.logging;

import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class NetworkLogger {
    private static final Logger logger = LoggerFactory.getLogger(NetworkLogger.class);
    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public void logPacket(Packet packet) {
        try {
            StringBuilder logMessage = new StringBuilder();
            logMessage.append("Paquet capturé [").append(LocalDateTime.now().format(formatter)).append("] ");

            IpPacket ipPacket = packet.get(IpPacket.class);
            if (ipPacket != null) {
                logMessage.append("IP: ")
                        .append(ipPacket.getHeader().getSrcAddr())
                        .append(" -> ")
                        .append(ipPacket.getHeader().getDstAddr())
                        .append(" | ");

                TcpPacket tcpPacket = packet.get(TcpPacket.class);
                if (tcpPacket != null) {
                    logMessage.append("TCP | ")
                            .append("Ports: ")
                            .append(tcpPacket.getHeader().getSrcPort())
                            .append(" -> ")
                            .append(tcpPacket.getHeader().getDstPort());
                }

                UdpPacket udpPacket = packet.get(UdpPacket.class);
                if (udpPacket != null) {
                    logMessage.append("UDP | ")
                            .append("Ports: ")
                            .append(udpPacket.getHeader().getSrcPort())
                            .append(" -> ")
                            .append(udpPacket.getHeader().getDstPort());
                }
            }

            logger.info(logMessage.toString());
        } catch (Exception e) {
            logger.error("Erreur lors de la journalisation du paquet", e);
        }
    }

    public void logSecurityEvent(String message) {
        logger.warn("Alerte sécurité: {}", message);
    }
}