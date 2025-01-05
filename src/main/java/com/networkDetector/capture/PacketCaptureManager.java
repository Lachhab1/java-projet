package com.networkDetector.capture;

import com.networkDetector.filter.AdvancedPacketFilter;
import com.networkDetector.logging.NetworkLogger;
import com.networkDetector.storage.PacketStorageManager;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

public class PacketCaptureManager {
    private static final Logger logger = LoggerFactory.getLogger(PacketCaptureManager.class);
    private static final int SNAPLEN = 65536;
    private static final int TIMEOUT = 1000;

    private final NetworkInterfaceHandler interfaceHandler;
    private final AdvancedPacketFilter packetFilter;
    private final PacketStorageManager packetStorage;
    private final NetworkLogger networkLogger;

    private final AtomicBoolean isCapturing = new AtomicBoolean(false);
    private volatile ExecutorService executor;
    private volatile PcapHandle handle;
    private final Object lock = new Object();

    public PacketCaptureManager(
            NetworkInterfaceHandler interfaceHandler,
            NetworkLogger networkLogger,
            PacketStorageManager packetStorage) {
        this.interfaceHandler = interfaceHandler;
        this.networkLogger = networkLogger;
        this.packetStorage = packetStorage;
        this.packetFilter = new AdvancedPacketFilter(networkLogger);
    }

    // Add back the overloaded method
    public void startCapture(PcapNetworkInterface networkInterface) {
        synchronized (lock) {
            if (isCapturing.get()) {
                logger.warn("Capture is already in progress");
                return;
            }

            try {
                if (networkInterface == null) {
                    throw new IllegalStateException("Network interface cannot be null");
                }

                // Create new executor if necessary
                if (executor == null || executor.isShutdown()) {
                    executor = Executors.newSingleThreadExecutor(r -> {
                        Thread thread = new Thread(r, "PacketCapture-Thread");
                        thread.setDaemon(true);
                        return thread;
                    });
                }

                // Open new handle
                handle = networkInterface.openLive(
                        SNAPLEN,
                        PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
                        TIMEOUT
                );

                isCapturing.set(true);

                // Submit capture task with error handling
                executor.submit(() -> {
                    try {
                        capturePackets();
                    } catch (Exception ex) {
                        logger.error("Capture task failed", ex);
                        stopCapture();
                    }
                });

                logger.info("Capture started on interface {}", networkInterface.getName());
            } catch (Exception e) {
                logger.error("Unable to start capture", e);
                cleanupResources();
                throw new RuntimeException("Failed to start capture", e);
            }
        }
    }

    public void startCapture() {
        try {
            PcapNetworkInterface networkInterface = interfaceHandler.getSelectedInterface();
            if (networkInterface == null) {
                throw new IllegalStateException("No network interface selected");
            }
            startCapture(networkInterface);
        } catch (Exception e) {
            logger.error("Unable to start capture", e);
            throw new RuntimeException("Failed to start capture", e);
        }
    }

    private void capturePackets() {
        try {
            while (isCapturing.get() && handle != null && handle.isOpen()) {
                try {
                    Packet packet = handle.getNextPacket();
                    if (packet != null && packetFilter.shouldProcessPacket(packet)) {
                        processPacket(packet);
                    }

                    // Small delay to prevent CPU overload
                    Thread.sleep(10);
                } catch (NotOpenException e) {
                    if (isCapturing.get()) {
                        logger.error("Handle closed unexpectedly", e);
                        break;
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        } catch (Exception e) {
            logger.error("Error in capture loop", e);
        } finally {
            cleanupResources();
        }
    }

    private void processPacket(Packet packet) {
        try {
            packetStorage.storePacket(packet);
            networkLogger.logPacket(packet);
        } catch (Exception e) {
            logger.error("Error processing packet", e);
        }
    }

    public void stopCapture() {
        synchronized (lock) {
            if (!isCapturing.get()) {
                return;
            }

            isCapturing.set(false);
            cleanupResources();
            logger.info("Network capture stopped");
        }
    }

    private void cleanupResources() {
        // Close handle
        if (handle != null) {
            try {
                if (handle.isOpen()) {
                    handle.close();
                }
            } catch (Exception e) {
                logger.warn("Error closing handle", e);
            } finally {
                handle = null;
            }
        }

        // Shutdown executor
        if (executor != null && !executor.isShutdown()) {
            try {
                executor.shutdown();
                if (!executor.awaitTermination(2, TimeUnit.SECONDS)) {
                    executor.shutdownNow();
                }
            } catch (InterruptedException e) {
                executor.shutdownNow();
                Thread.currentThread().interrupt();
            } finally {
                executor = null;
            }
        }
    }

    public boolean isCapturing() {
        return isCapturing.get();
    }

    public String getStatistics() {
        if (handle != null && handle.isOpen()) {
            try {
                PcapStat stats = handle.getStats();
                return String.format("Received: %d, Dropped: %d, Interface Dropped: %d",
                        stats.getNumPacketsReceived(),
                        stats.getNumPacketsDropped(),
                        stats.getNumPacketsDroppedByIf());
            } catch (PcapNativeException | NotOpenException e) {
                logger.error("Unable to get statistics", e);
            }
        }
        return "Statistics unavailable";
    }
}