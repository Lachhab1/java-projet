package com.project.Intrusion;

import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class App {
    private static final Logger logger = LoggerFactory.getLogger(App.class);
    private static final int SNAP_LEN = 64 * 1024;
    private static final int TIMEOUT = 10; // ms

    public static void main(String[] args) {
        try {
            // Liste les interfaces disponibles
//            listNetworkInterfaces();

            // Choisissez votre interface (en0 pour WiFi, en1 pour Ethernet, etc.)
            String interfaceName = "en0"; // Change this if needed

            // Capture des paquets
            capturePackets(interfaceName, 1000); // Capture 10 paquets
        } catch (Exception e) {
            logger.error("Erreur lors de la capture de paquets", e);
        }
    }

    private static void listNetworkInterfaces() throws PcapNativeException {
        logger.info("Interfaces réseau disponibles :");
        for (PcapNetworkInterface nif : Pcaps.findAllDevs()) {
            logger.info("- {} : {}", nif.getName());
        }
    }

    private static void capturePackets(String interfaceName, int packetCount) throws PcapNativeException, NotOpenException {
        PcapNetworkInterface nif = Pcaps.getDevByName(interfaceName);
        if (nif == null) {
            logger.error("Interface {} non trouvée", interfaceName);
            return;
        }

        try (PcapHandle handle = nif.openLive(SNAP_LEN,
                PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, TIMEOUT)) {

            logger.info("Début de la capture sur l'interface {}", interfaceName);

            // Filtre pour ne capturer que les paquets TCP
            handle.setFilter("tcp", BpfProgram.BpfCompileMode.OPTIMIZE);

            // Capture des paquets
            for (int i = 0; i < packetCount; i++) {
                Packet packet = handle.getNextPacket();
                if (packet != null) {
                    analyzePacket(packet);
                }
            }
        } catch (PcapNativeException | NotOpenException e) {
            logger.error("Erreur lors de la capture de paquets", e);
        }
    }

    private static void analyzePacket(Packet packet) {
        // Analyse basique du paquet
        logger.info("Paquet capturé:");
        logger.info("- Longueur: {} octets", packet.length());

        // détails ici
        if (packet.contains(org.pcap4j.packet.TcpPacket.class)) {
            org.pcap4j.packet.TcpPacket tcpPacket = packet.get(org.pcap4j.packet.TcpPacket.class);
            logger.info("- Paquet TCP");
            logger.info("  - Port source: {}", tcpPacket.getHeader().getSrcPort());
            logger.info("  - Port destination: {}", tcpPacket.getHeader().getDstPort());
        }
    }
}
