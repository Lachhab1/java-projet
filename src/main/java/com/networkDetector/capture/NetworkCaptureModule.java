package com.networkDetector.capture;

import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class NetworkCaptureModule {
    private static final Logger logger = LoggerFactory.getLogger(NetworkCaptureModule.class);

    // Configuration paramétrable
    private static final int DEFAULT_PACKET_COUNT = 100;
    private static final int SNAPSHOT_LENGTH = 65536;
    private static final int READ_TIMEOUT = 50;

    private PcapNetworkInterface networkInterface;
    private volatile boolean isCapturing = false;
    private ExecutorService executor;
    private PcapHandle handle;

    public NetworkCaptureModule() throws PcapNativeException {
        // Afficher toutes les interfaces disponibles
        List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();

        if (interfaces.isEmpty()) {
            throw new PcapNativeException("Aucune interface réseau trouvée");
        }

        // Log de toutes les interfaces
        for (PcapNetworkInterface inter : interfaces) {
            logger.info("Interface disponible : {} ({})",
                    inter.getName(),
                    inter.getAddresses().stream().findFirst().map(Object::toString).orElse("No address")
            );
        }

        // Sélection de l'interface par défaut
        this.networkInterface = selectNetworkInterface(interfaces);
        logger.info("Interface sélectionnée : {}", networkInterface.getName());
    }

    /**
    /**
     * Sélection intelligente de l'interface réseau, priorisant 'en0'.
     */
    private PcapNetworkInterface selectNetworkInterface(List<PcapNetworkInterface> interfaces) {
        // Rechercher l'interface 'en0' en priorité
        return interfaces.stream()
                .filter(inter -> "en0".equals(inter.getName()))
                .findFirst()
                .orElseGet(() -> {
                    // Sinon, préférer les interfaces non-loopback et actives
                    return interfaces.stream()
                            .filter(inter -> !inter.getName().contains("lo") &&
                                    !inter.getName().contains("docker") &&
                                    inter.isUp())
                            .findFirst()
                            .orElse(interfaces.get(0)); // Fallback à la première interface si aucune ne correspond
                });
    }


    /**
     * Démarrage de la capture de paquets
     */
    public void startCapture() {
        if (isCapturing) {
            logger.warn("La capture est déjà en cours");
            return;
        }

        try {
            // Mode promiscuous avec timeout configurable
            PcapNetworkInterface.PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;

            // Ouvrir l'interface réseau avec gestion explicite
            handle = networkInterface.openLive(SNAPSHOT_LENGTH, mode, READ_TIMEOUT);

            executor = Executors.newSingleThreadExecutor();
            isCapturing = true;

            executor.submit(() -> {
                try {
                    capturePackets();
                } catch (Exception e) {
                    logger.error("Erreur lors de la capture", e);
                } finally {
                    stopCapture();
                }
            });

            logger.info("Capture démarrée sur l'interface {}", networkInterface.getName());
        } catch (Exception e) {
            logger.error("Impossible de démarrer la capture", e);
        }
    }

    /**
     * Logique de capture des paquets
     */
    private void capturePackets() throws PcapNativeException, NotOpenException {
        int packetCount = 0;
        while (isCapturing && packetCount < DEFAULT_PACKET_COUNT) {
            Packet packet = handle.getNextPacket();
            if (packet != null) {
                processPacket(packet);
                packetCount++;
            }

            // Petit délai pour réduire la charge CPU
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    /**
     * Traitement avancé des paquets
     */
    private void processPacket(Packet packet) {
        try {
//            // Extraction et log des informations importantes
            logger.info("Paquet capturé - Taille: {} octets", packet.length());
             logger.info(packet.toString());

        } catch (Exception e) {
            logger.error("Erreur lors du traitement du paquet", e);
        }
    }

    /**
     * Arrêt propre de la capture
     */
    public void stopCapture() {
        isCapturing = false;

        // Fermer le handle réseau
        if (handle != null) {
            handle.close();
        }

        // Arrêter l'executor
        if (executor != null) {
            executor.shutdown();
            try {
                if (!executor.awaitTermination(1, TimeUnit.SECONDS)) {
                    executor.shutdownNow();
                }
            } catch (InterruptedException e) {
                executor.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }

        logger.info("Capture réseau arrêtée");
    }

    /**
     * Méthode principale de test
     */
//    public static void main(String[] args) {
//        try {
//            NetworkCaptureModule captureModule = new NetworkCaptureModule();
//            captureModule.startCapture();
//
//            // Capture pendant 10 secondes
//            Thread.sleep(10000);
//
//            captureModule.stopCapture();
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//    }
}