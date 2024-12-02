package com.project.Intrusion;

import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class App {
    private static final Logger logger = LoggerFactory.getLogger(NetworkSniffer.class);
    private static final int SNAP_LEN = 64 * 1024;
    private static final int TIMEOUT = 10; // ms

    public static void main(String[] args) {
        try {
            // Liste les interfaces disponibles
            listNetworkInterfaces();

            // Choisissez votre interface (en0 pour WiFi, en1 pour Ethernet, etc.)
            String interfaceName = "en0";

            // Capture des paquets
            capturePackets(interfaceName, 10); // Capture 10 paquets
        } catch (Exception e) {
            logger.error("Erreur lors de la capture de paquets", e);
        }
    }

    private static void listNetworkInterfaces() throws PcapNativeException {
        logger.info("Interfaces réseau disponibles :");
        for (PcapNetworkInterface nif : Pcaps.findAllDevs()) {
            logger.info("- {} : {}", nif.getName(), nif.getDescription());
        }
    }

    private static void capturePackets(String interfaceName, int packetCount) throws PcapNativeException, NotOpenException {
        // Ouvrir l'interface réseau
        try (PcapHandle handle = Pcaps.getDevByName(interfaceName).openLive(SNAP_LEN,
                PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, TIMEOUT)) {

            logger.info("Début de la capture sur l'interface {}", interfaceName);

            // Filtre pour ne capturer que les paquets TCP (optionnel)
            handle.setFilter("tcp", BpfProgram.BpfCompileMode.OPTIMIZE);

            // Capture des paquets
            for (int i = 0; i < packetCount; i++) {
                Packet packet = handle.getNextPacketEx();
                if (packet != null) {
                    analyzePacket(packet);
                }
            }
        }
    }

    private static void analyzePacket(Packet packet) {
        // Analyse basique du paquet
        logger.info("Paquet capturé:");
        logger.info("- Longueur: {} octets", packet.length());

        // Vous pouvez ajouter plus de détails ici
        // Exemple : afficher les en-têtes, l'adresse source/destination, etc.
        if (packet.contains(org.pcap4j.packet.TcpPacket.class)) {
            org.pcap4j.packet.TcpPacket tcpPacket = packet.get(org.pcap4j.packet.TcpPacket.class);
            logger.info("- Paquet TCP");
            logger.info("  - Port source: {}", tcpPacket.getHeader().getSrcPort());
            logger.info("  - Port destination: {}", tcpPacket.getHeader().getDstPort());
        }
    }
}