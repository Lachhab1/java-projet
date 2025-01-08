package com.networkDetector;

import com.networkDetector.capture.NetworkInterfaceHandler;
import com.networkDetector.capture.PacketCaptureManager;
import com.networkDetector.logging.NetworkLogger;
import com.networkDetector.protocol.analyzer.ProtocolAnalyzer;
import com.networkDetector.protocol.model.ProtocolData;
import com.networkDetector.protocol.model.ThreatLevel;
import com.networkDetector.storage.PacketDTO;
import com.networkDetector.storage.PacketStorageManager;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNativeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class NetworkIntrusionDetector {
    private static final Logger logger = LoggerFactory.getLogger(NetworkIntrusionDetector.class);
    private static final int SHUTDOWN_TIMEOUT_SECONDS = 5;
    private static final String DEFAULT_INTERFACE = "en0";

    private final PacketCaptureManager captureManager;
    private final NetworkLogger networkLogger;
    private final PacketStorageManager storageManager;
    private final NetworkInterfaceHandler interfaceHandler;
    private final ProtocolAnalyzer protocolAnalyzer;
    private final ConcurrentLinkedQueue<ProtocolData> threatAlerts;
    private final Set<String> detectedThreats;
    private ExecutorService monitoringExecutor;
    private final AtomicBoolean isRunning;

    public NetworkIntrusionDetector() {
        this.networkLogger = new NetworkLogger();
        this.storageManager = new PacketStorageManager();
        this.interfaceHandler = new NetworkInterfaceHandler();
        this.protocolAnalyzer = new ProtocolAnalyzer(networkLogger);
        this.threatAlerts = new ConcurrentLinkedQueue<>();
        this.detectedThreats = new HashSet<>();
        this.monitoringExecutor = Executors.newSingleThreadExecutor();
        this.isRunning = new AtomicBoolean(false);

        try {
            PcapNetworkInterface defaultInterface = interfaceHandler.selectDefaultInterface();
            if (defaultInterface != null) {
                interfaceHandler.selectDefaultInterface();
            } else {
                logger.warn("Default interface {} not found, will select first available interface", DEFAULT_INTERFACE);
            }
        } catch (PcapNativeException e) {
            logger.error("Error initializing network interface: {}", e.getMessage());
        }

        this.captureManager = new PacketCaptureManager(interfaceHandler, networkLogger, storageManager);
    }

    public void startCapture(PcapNetworkInterface networkInterface) {
        if (isRunning.compareAndSet(false, true)) {
            try {
                logger.info("Starting network intrusion detector on interface {}", networkInterface.getName());
                interfaceHandler.selectInterfaceByName(networkInterface.getName());
                captureManager.startCapture(networkInterface);
                startMonitoring();
            } catch (Exception e) {
                logger.error("Failed to start capture: {}", e.getMessage());
                isRunning.set(false);
                throw new RuntimeException("Failed to start capture", e);
            }
        } else {
            logger.warn("Capture already running");
        }
    }

    public void start() {
        if (isRunning.compareAndSet(false, true)) {
            try {
                PcapNetworkInterface selectedInterface = interfaceHandler.getSelectedInterface();
                if (selectedInterface == null) {
                    List<PcapNetworkInterface> interfaces = interfaceHandler.listAllInterfaces();
                    if (!interfaces.isEmpty()) {
                        selectedInterface = interfaces.get(0);
                        interfaceHandler.selectInterfaceByName(selectedInterface.getName());
                    } else {
                        throw new RuntimeException("No network interfaces available");
                    }
                }

                logger.info("Starting network intrusion detector on interface {}", selectedInterface.getName());
                captureManager.startCapture();
                startMonitoring();
            } catch (Exception e) {
                logger.error("Failed to start capture: {}", e.getMessage());
                isRunning.set(false);
                throw new RuntimeException("Failed to start capture", e);
            }
        } else {
            logger.warn("Capture already running");
        }
    }

    public void stop() {
        if (isRunning.compareAndSet(true, false)) {
            logger.info("Stopping network intrusion detector");
            try {
                captureManager.stopCapture();
                shutdownExecutor();
            } catch (Exception e) {
                logger.error("Error during shutdown: {}", e.getMessage());
            }
        }
    }

    private void shutdownExecutor() {
        if (monitoringExecutor != null) {
            monitoringExecutor.shutdown();
            try {
                if (!monitoringExecutor.awaitTermination(SHUTDOWN_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                    monitoringExecutor.shutdownNow();
                }
            } catch (InterruptedException e) {
                monitoringExecutor.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
    }

    private void startMonitoring() {
        // Reinitialize the executor
        if (monitoringExecutor.isTerminated()) {
            monitoringExecutor = Executors.newSingleThreadExecutor();
        }
        monitoringExecutor.submit(() -> {
            while (isRunning.get() && !Thread.currentThread().isInterrupted()) {
                try {
                    List<PacketDTO> packets = getCapturedPackets();
                    if (!packets.isEmpty()) {
                        logger.debug("Currently captured packets: {}", packets.size());
                        for (PacketDTO packet : packets) {
                            analyzePacket(packet);
                        }
                    }
                    TimeUnit.SECONDS.sleep(5);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        });
    }

    private void analyzePacket(PacketDTO packetDTO) {
        ProtocolData protocolData = protocolAnalyzer.analyzePacket(packetDTO.getPacket());
        if (protocolData != null && protocolData.getThreatLevel() != ThreatLevel.LOW) {
            String threatKey = generateThreatKey(protocolData);
            if (!detectedThreats.contains(threatKey)) {
                detectedThreats.add(threatKey);
                threatAlerts.add(protocolData);
            }
        }
    }

    private void analyzeCapturedPackets() {
        List<PacketDTO> packets = getCapturedPackets();
        for (PacketDTO packet : packets) {
            analyzePacket(packet);
        }
    }

    private String generateThreatKey(ProtocolData protocolData) {
        return protocolData.getSourceAddress() + ":" + protocolData.getSourcePort() + "->" +
                protocolData.getDestinationAddress() + ":" + protocolData.getDestinationPort() + ":" +
                protocolData.getThreatLevel();
    }

    public List<PacketDTO> getCapturedPackets() {
        return storageManager.getCapturedPackets();
    }

    public String getStatistics() {
        return captureManager.getStatistics();
    }

    public List<PcapNetworkInterface> getAvailableInterfaces() throws PcapNativeException {
        return interfaceHandler.listAllInterfaces();
    }

    public void printCapturedPacketsJson() {
        List<PacketDTO> packets = getCapturedPackets();
        if (packets.isEmpty()) {
            System.out.println("No packets captured yet");
            return;
        }

        System.out.println("Captured Packets JSON:");
        packets.forEach(packet -> {
            System.out.println("-------------------");
            System.out.println(packet);
        });
    }

    public void savePacketsToFile(String filename) throws IOException {
        List<PacketDTO> packets = getCapturedPackets();
        List<String> packetJsonList = packets.stream()
                .map(PacketDTO::toString)
                .toList();
        Files.write(Paths.get(filename), packetJsonList);
    }

    public ConcurrentLinkedQueue<ProtocolData> getThreatAlerts() {
        return threatAlerts;
    }

    public List<Double> getTrafficData() {
        return captureManager.getTrafficData();
    }

    public void clearCapturedData() {
        captureManager.clearCapturedData();
        threatAlerts.clear();
        detectedThreats.clear();
        storageManager.clearCapturedData();
    }

    public static void main(String[] args) {
        NetworkIntrusionDetector detector = new NetworkIntrusionDetector();
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            logger.info("Shutdown hook triggered, stopping detector...");
            detector.stop();
        }));

        try {
            NetworkInterfaceHandler interfaceHandler = new NetworkInterfaceHandler();
            PcapNetworkInterface defaultInterface = interfaceHandler.selectInterfaceByName(DEFAULT_INTERFACE);
            if (defaultInterface != null) {
                interfaceHandler.selectDefaultInterface();
            } else {
                logger.warn("Default interface {} not found, will select first available interface", DEFAULT_INTERFACE);
            }

            detector.startCapture(defaultInterface);
            while (true) {
                Thread.sleep(30000);
                detector.printCapturedPacketsJson();
                detector.savePacketsToFile("captured_packets.json");
            }
        } catch (Exception e) {
            logger.error("Failed to start detector: {}", e.getMessage());
            System.exit(1);
        }
    }
}