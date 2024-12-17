package com.networkDetector.filter;

import com.networkDetector.logging.NetworkLogger;
import com.networkDetector.model.FilterConfig;
import com.networkDetector.model.NetworkStatistics;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.Inet4Address;

public class AdvancedPacketFilter {
    private static final Logger logger = LoggerFactory.getLogger(AdvancedPacketFilter.class);

    private final NetworkStatistics statistics;
    private final NetworkLogger networkLogger;

    public AdvancedPacketFilter(NetworkLogger networkLogger) {
        this.networkLogger = networkLogger;
        this.statistics = new NetworkStatistics();
    }

    public boolean shouldProcessPacket(Packet packet) {
        try {
            IpPacket ipPacket = packet.get(IpPacket.class);
            if (ipPacket == null) {
                return false;
            }

            Inet4Address sourceIP = (Inet4Address) ipPacket.getHeader().getSrcAddr();
            String sourceIPStr = sourceIP.getHostAddress();

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

            // Analyse des ports TCP
            TcpPacket tcpPacket = packet.get(TcpPacket.class);
            if (tcpPacket != null) {
                int srcPort = tcpPacket.getHeader().getSrcPort().valueAsInt();
                int dstPort = tcpPacket.getHeader().getDstPort().valueAsInt();

                if (FilterConfig.SUSPICIOUS_PORTS.contains(srcPort) ||
                        FilterConfig.SUSPICIOUS_PORTS.contains(dstPort)) {
                    networkLogger.logSecurityEvent(String.format(
                            "Port suspect détecté - Source: %s, Ports: %d/%d",
                            sourceIPStr, srcPort, dstPort
                    ));
                    return false;
                }
            }

            // Vérification du taux de paquets
            statistics.recordConnection(sourceIPStr);
            if (statistics.checkPacketRateExceeded(sourceIPStr, System.currentTimeMillis())) {
                networkLogger.logSecurityEvent("Taux de paquets élevé depuis : " + sourceIPStr);
                return false;
            }

            return true;
        } catch (Exception e) {
            logger.error("Erreur lors du filtrage du paquet", e);
            return false;
        }
    }
}
