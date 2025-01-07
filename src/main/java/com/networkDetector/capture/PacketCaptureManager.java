package com.networkDetector.capture;

import com.networkDetector.filter.AdvancedPacketFilter;
import com.networkDetector.logging.NetworkLogger;
import com.networkDetector.protocol.analyzer.ProtocolAnalyzer;
import com.networkDetector.protocol.model.ProtocolData;
import com.networkDetector.protocol.model.ThreatLevel;
import com.networkDetector.storage.PacketDTO;
import com.networkDetector.storage.PacketStorageManager;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

public class PacketCaptureManager {
    private static final Logger logger = LoggerFactory.getLogger(PacketCaptureManager.class);
    private final ProtocolAnalyzer protocolAnalyzer;
    private final NetworkInterfaceHandler interfaceHandler;
    private final AdvancedPacketFilter packetFilter;
    private final PacketStorageManager packetStorage;
    private final NetworkLogger networkLogger;
    private final ConcurrentLinkedQueue<ProtocolData> threatAlerts;
    private final ConcurrentLinkedQueue<PacketDTO> capturedPackets;
    private final AtomicInteger totalPackets;
    private final AtomicInteger totalPacketSize;
    private volatile boolean isCapturing = false;
    private ExecutorService executor;
    private PcapHandle handle;

    public PacketCaptureManager(
            NetworkInterfaceHandler interfaceHandler,
            NetworkLogger networkLogger,
            PacketStorageManager packetStorage) {
        this.interfaceHandler = interfaceHandler;
        this.networkLogger = networkLogger;
        this.packetStorage = packetStorage;
        this.packetFilter = new AdvancedPacketFilter(networkLogger);
        this.protocolAnalyzer = new ProtocolAnalyzer(networkLogger);
        this.threatAlerts = new ConcurrentLinkedQueue<>();
        this.capturedPackets = new ConcurrentLinkedQueue<>();
        this.totalPackets = new AtomicInteger(0);
        this.totalPacketSize = new AtomicInteger(0);
    }

    public void startCapture() {
        if (isCapturing) {
            logger.warn("Capture is already in progress");
            return;
        }

        try {
            PcapNetworkInterface networkInterface = interfaceHandler.getSelectedInterface();
            handle = networkInterface.openLive(65536,
                    PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 1000);

            executor = Executors.newSingleThreadExecutor();
            isCapturing = true;

            executor.submit(() -> {
                try {
                    capturePackets();
                } catch (Exception e) {
                    logger.error("Error during capture", e);
                } finally {
                    stopCapture();
                }
            });

            logger.info("Capture started on interface {}", networkInterface.getName());
        } catch (Exception e) {
            logger.error("Unable to start capture", e);
        }
    }

    public void startCapture(PcapNetworkInterface networkInterface) {
        if (isCapturing) {
            logger.warn("Capture is already in progress");
            return;
        }

        try {
            handle = networkInterface.openLive(65536,
                    PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);

            executor = Executors.newSingleThreadExecutor();
            isCapturing = true;

            executor.submit(() -> {
                try {
                    capturePackets();
                } catch (Exception e) {
                    logger.error("Error during capture", e);
                } finally {
                    stopCapture();
                }
            });

            logger.info("Capture started on interface {}", networkInterface.getName());
        } catch (Exception e) {
            logger.error("Unable to start capture", e);
        }
    }

    private void capturePackets() throws PcapNativeException, NotOpenException {
        while (isCapturing) {
            Packet packet = handle.getNextPacket();
            if (packet != null && packetFilter.shouldProcessPacket(packet)) {
                processPacket(packet);
            }

            // Small delay to reduce CPU load
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    private void handleThreat(ProtocolData protocolData) {
        // Implement threat handling logic
        networkLogger.logSecurityEvent(
                String.format("Threat detected: %s from %s",
                        protocolData.getThreatLevel(),
                        protocolData.getSourceAddress()));
        threatAlerts.add(protocolData);
    }

    private void processPacket(Packet packet) {
        try {
            // Store the packet
            packetStorage.storePacket(packet);
            capturedPackets.add(packetStorage.getCapturedPackets().get(packetStorage.getStoredPacketCount() - 1));
            // update statistics
            totalPackets.incrementAndGet();
            totalPacketSize.addAndGet(packet.getPayload().length());
            // Analyze the packet
            if (packet != null) {
                ProtocolData protocolData = protocolAnalyzer.analyzePacket(packet);
                if (protocolData != null &&
                        protocolData.getThreatLevel().getLevel() >= ThreatLevel.MEDIUM.getLevel()) {
                    // Handle detected threats
                    threatAlerts.offer(protocolData);
                    handleThreat(protocolData);
                }
            }
            // Detailed log
            networkLogger.logPacket(packet);
        } catch (Exception e) {
            logger.error("Error processing packet", e);
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

        logger.info("Network capture stopped");
    }

    public String getStatistics() {
        int totalPackets = this.totalPackets.get();
        double averageSize = totalPackets > 0 ? (double) totalPacketSize.get() / totalPackets : 0;
        double bandwidth = totalPackets > 0 ? (double) totalPacketSize.get() * 8 / (totalPackets * 10) : 0;

        return String.format("Total Packets: %d\nAverage Size: %.2f bytes\nBandwidth: %.2f Mbps",
                totalPackets, averageSize, bandwidth);
    }

    public ConcurrentLinkedQueue<ProtocolData> getThreatAlerts() {
        return threatAlerts;
    }

    public List<Double> getTrafficData() {
        return capturedPackets.stream()
                .map(PacketDTO::getLength)
                .map(length -> (double) length)
                .collect(Collectors.toList());
    }
}