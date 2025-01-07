package com.networkDetector;

import com.networkDetector.capture.NetworkInterfaceHandler;
import com.networkDetector.capture.PacketCaptureManager;
import com.networkDetector.logging.NetworkLogger;
import com.networkDetector.protocol.analyzer.ProtocolAnalyzer;
import com.networkDetector.protocol.model.ProtocolData;
import com.networkDetector.storage.PacketDTO;
import com.networkDetector.storage.PacketStorageManager;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNativeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class NetworkIntrusionDetector {
    private static final Logger logger = LoggerFactory.getLogger(NetworkIntrusionDetector.class);
    private static final int SHUTDOWN_TIMEOUT_SECONDS = 5;
    private static final String DEFAULT_INTERFACE = "Ethernet";

    private final PacketCaptureManager captureManager;
    private final NetworkLogger networkLogger;
    private final PacketStorageManager storageManager;
    private final NetworkInterfaceHandler interfaceHandler;
    private final ExecutorService monitoringExecutor;
    private final AtomicBoolean isRunning;

    public NetworkIntrusionDetector() {
        this.networkLogger = new NetworkLogger();
        this.storageManager = new PacketStorageManager();
        this.interfaceHandler = new NetworkInterfaceHandler();
        this.monitoringExecutor = Executors.newSingleThreadExecutor();
        this.isRunning = new AtomicBoolean(false);

        // Initialize interface handler with better error handling
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

    private void startMonitoring() {
        monitoringExecutor.submit(() -> {
            while (isRunning.get() && !Thread.currentThread().isInterrupted()) {
                try {
                    List<PacketDTO> packets = getCapturedPackets();
                    if (!packets.isEmpty()) {
                        logger.debug("Currently captured packets: {}", Optional.of(packets.size()));
                    }
                    TimeUnit.SECONDS.sleep(5);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        });
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
        return captureManager.getThreatAlerts();
    }

    public List<Double> getTrafficData() {
        return captureManager.getTrafficData();
    }

    public static void main(String[] args) {
        NetworkIntrusionDetector detector = new NetworkIntrusionDetector();
        // Improved shutdown hook
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
            // Print JSON every 10 seconds
            while (true) {
                Thread.sleep(30000);
                detector.printCapturedPacketsJson();
                // Save packets to file every 30 seconds
                detector.savePacketsToFile("captured_packets.json");
            }
        } catch (Exception e) {
            logger.error("Failed to start detector: {}", e.getMessage());
            System.exit(1);
        }
    }
}