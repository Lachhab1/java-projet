package com.networkDetector.filter;

import com.networkDetector.logging.NetworkLogger;
import com.networkDetector.model.FilterConfig;
import com.networkDetector.model.NetworkStatistics;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.Optional;

public class AdvancedPacketFilter {
    private static final Logger logger = LoggerFactory.getLogger(AdvancedPacketFilter.class);

    private final NetworkStatistics statistics;
    private final NetworkLogger networkLogger;

    public AdvancedPacketFilter(NetworkLogger networkLogger) {
        this.networkLogger = networkLogger;
        this.statistics = new NetworkStatistics();
    }

    public boolean shouldProcessPacket(Packet packet) {
        if (packet == null) {
            return false;
        }

        try {
            Optional<IpPacket> ipPacketOpt = Optional.ofNullable(packet.get(IpPacket.class));
            return ipPacketOpt.map(this::processIpPacket).orElse(false);
        } catch (Exception e) {
            logger.error("Erreur lors du filtrage du paquet: {}", e.getMessage());
            return false;
        }
    }

    private boolean processIpPacket(IpPacket ipPacket) {
        try {
            InetAddress sourceIP = ipPacket.getHeader().getSrcAddr();
            InetAddress destIP = ipPacket.getHeader().getDstAddr();

            // Early return for null addresses
            if (sourceIP == null || destIP == null) {
                logger.warn("Adresse IP null détectée");
                return false;
            }

            String sourceIPStr = sourceIP.getHostAddress();
            String destIPStr = destIP.getHostAddress();

            // Safe multicast check
            if (isMulticastAddress(sourceIP) || isMulticastAddress(destIP)) {
                logger.debug("Paquet multicast ignoré: {} -> {}", sourceIPStr, destIPStr);
                return false;
            }

            // Handle IPv6 packets specifically
            if (ipPacket instanceof IpV6Packet) {
                return handleIPv6Packet((IpV6Packet) ipPacket, sourceIPStr);
            }

            // Continue with normal packet processing
            return processNormalPacket(ipPacket, sourceIP, sourceIPStr);

        } catch (Exception e) {
            logger.error("Erreur lors du traitement du paquet IP: {}", e.getMessage());
            return false;
        }
    }

    private boolean isMulticastAddress(InetAddress addr) {
        try {
            return addr != null && addr.isMulticastAddress();
        } catch (Exception e) {
            logger.warn("Erreur lors de la vérification multicast: {}", e.getMessage());
            return false;
        }
    }

    private boolean handleIPv6Packet(IpV6Packet ipv6Packet, String sourceIPStr) {
        try {
            // Special handling for IPv6 packets
            if (FilterConfig.BLOCKED_IPS.contains(sourceIPStr)) {
                networkLogger.logSecurityEvent("IPv6 bloqué - IP suspecte : " + sourceIPStr);
                return false;
            }

            // Process transport layer protocols
            return processTransportLayer(ipv6Packet, sourceIPStr);
        } catch (Exception e) {
            logger.error("Erreur lors du traitement du paquet IPv6: {}", e.getMessage());
            return false;
        }
    }

    private boolean processNormalPacket(IpPacket ipPacket, InetAddress sourceIP, String sourceIPStr) {
        // Vérification des IP bloquées
        if (FilterConfig.BLOCKED_IPS.contains(sourceIPStr)) {
            networkLogger.logSecurityEvent("Paquet bloqué - IP suspecte : " + sourceIPStr);
            return false;
        }

        // Vérification des connexions suspectes
        if (statistics.isConnectionSuspicious(sourceIPStr)) {
            networkLogger.logSecurityEvent("Connexion suspecte détectée depuis : " + sourceIPStr);
            return false;
        }

        // Process transport layer protocols
        if (!processTransportLayer(ipPacket, sourceIPStr)) {
            return false;
        }

        // Vérification du taux de paquets
        statistics.recordConnection(sourceIPStr);
        return !statistics.checkPacketRateExceeded(sourceIPStr, System.currentTimeMillis());
    }

    private boolean processTransportLayer(IpPacket ipPacket, String sourceIPStr) {
        try {
            TcpPacket tcpPacket = ipPacket.get(TcpPacket.class);
            if (tcpPacket != null) {
                return processTcpPacket(tcpPacket, sourceIPStr);
            }

            UdpPacket udpPacket = ipPacket.get(UdpPacket.class);
            if (udpPacket != null) {
                return processUdpPacket(udpPacket, sourceIPStr);
            }

            return true;
        } catch (Exception e) {
            logger.error("Erreur lors du traitement de la couche transport: {}", e.getMessage());
            return false;
        }
    }

    private boolean processTcpPacket(TcpPacket tcpPacket, String sourceIPStr) {
        try {
            int srcPort = tcpPacket.getHeader().getSrcPort().valueAsInt();
            int dstPort = tcpPacket.getHeader().getDstPort().valueAsInt();

            if (FilterConfig.SUSPICIOUS_PORTS.contains(srcPort) ||
                    FilterConfig.SUSPICIOUS_PORTS.contains(dstPort)) {
                networkLogger.logSecurityEvent(String.format(
                        "Port TCP suspect détecté - Source: %s, Ports: %d/%d",
                        sourceIPStr, srcPort, dstPort
                ));
                return false;
            }
            return true;
        } catch (Exception e) {
            logger.error("Erreur lors du traitement du paquet TCP: {}", e.getMessage());
            return false;
        }
    }

    private boolean processUdpPacket(UdpPacket udpPacket, String sourceIPStr) {
        try {
            int srcPort = udpPacket.getHeader().getSrcPort().valueAsInt();
            int dstPort = udpPacket.getHeader().getDstPort().valueAsInt();

            if (FilterConfig.SUSPICIOUS_PORTS.contains(srcPort) ||
                    FilterConfig.SUSPICIOUS_PORTS.contains(dstPort)) {
                networkLogger.logSecurityEvent(String.format(
                        "Port UDP suspect détecté - Source: %s, Ports: %d/%d",
                        sourceIPStr, srcPort, dstPort
                ));
                return false;
            }
            return true;
        } catch (Exception e) {
            logger.error("Erreur lors du traitement du paquet UDP: {}", e.getMessage());
            return false;
        }
    }
}