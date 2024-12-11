package com.networkDetector.filter;

import com.networkDetector.logging.NetworkLogger;
import com.networkDetector.model.FilterConfig;
import com.networkDetector.model.NetworkStatistics;
import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.Inet4Address;

public class AdvancedPacketFilter {
    private static final Logger logger = LoggerFactory.getLogger(AdvancedPacketFilter.class);

    private final NetworkStatistics statistics = new NetworkStatistics();
    private final NetworkLogger networkLogger;

    public AdvancedPacketFilter(NetworkLogger networkLogger) {
        this.networkLogger = networkLogger;
    }

    public boolean shouldProcessPacket(Packet packet) {
        try {
            // Extraction des informations IP
            IpPacket ipPacket = packet.get(IpPacket.class);
            if (ipPacket == null) return false;

            Inet4Address sourceIP = (Inet4Address) ipPacket.getHeader().getSrcAddr();
            String sourceIPStr = sourceIP.getHostAddress();

            // Vérification des adresses IP bloquées
            if (FilterConfig.BLOCKED_IPS.contains(sourceIPStr)) {
                networkLogger.logSecurityEvent("Paquet bloqué - IP suspecte : " + sourceIPStr);
                return false;
            }

            // Vérification du taux de connexion
            if (statistics.isConnectionSuspicious(sourceIPStr)) {
                networkLogger.logSecurityEvent("Trop de connexions depuis : " + sourceIPStr);
                return false;
            }

            // Analyse des ports
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

            // Enregistrement et vérification du taux de paquets
            statistics.recordConnection(sourceIPStr);
            if (statistics.checkPacketRateExceeded(sourceIPStr, System.currentTimeMillis())) {
                networkLogger.logSecurityEvent("Taux de paquets suspect depuis : " + sourceIPStr);
                return false;
            }

            return true;
        } catch (Exception e) {
            logger.error("Erreur de filtrage du paquet", e);
            return false;
        }
    }
}
