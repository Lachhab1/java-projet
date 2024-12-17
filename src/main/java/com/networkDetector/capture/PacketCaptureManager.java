package com.networkDetector.capture;

import com.networkDetector.filter.AdvancedPacketFilter;
import com.networkDetector.logging.NetworkLogger;
import com.networkDetector.storage.PacketStorageManager;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class PacketCaptureManager {
    private static final Logger logger = LoggerFactory.getLogger(PacketCaptureManager.class);

    private final NetworkInterfaceHandler interfaceHandler;
    private final AdvancedPacketFilter packetFilter;
    private final PacketStorageManager packetStorage;
    private final NetworkLogger networkLogger;

    private volatile boolean isCapturing = false;
    private ExecutorService executor;
    private PcapHandle handle;

    public PacketCaptureManager(
            NetworkInterfaceHandler interfaceHandler,
            NetworkLogger networkLogger,
            PacketStorageManager packetStorage
    ) {
        this.interfaceHandler = interfaceHandler;
        this.networkLogger = networkLogger;
        this.packetStorage = packetStorage;
        this.packetFilter = new AdvancedPacketFilter(networkLogger);
    }

    public void startCapture() {
        if (isCapturing) {
            logger.warn("La capture est déjà en cours");
            return;
        }

        try {
            PcapNetworkInterface networkInterface = interfaceHandler.getSelectedInterface();
            handle = networkInterface.openLive(65536,
                    PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);

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

    private void capturePackets() throws PcapNativeException, NotOpenException {
        int packetCount = 0;
        while (isCapturing) {
            Packet packet = handle.getNextPacket();
            if (packet != null && packetFilter.shouldProcessPacket(packet)) {
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

    private void processPacket(Packet packet) {
        try {
            // Stocker le paquet
            packetStorage.storePacket(packet);

            // Log détaillé
            networkLogger.logPacket(packet);
        } catch (Exception e) {
            logger.error("Erreur lors du traitement du paquet", e);
        }
    }

    public void stopCapture() {
        isCapturing = false;

        if (handle != null) {
            handle.close();
        }

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
}