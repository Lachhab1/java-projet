package com.networkDetector.capture;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.pcap4j.core.*;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.ProtocolFamily;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class NetworkCaptureModule {
    private static final Logger logger = LoggerFactory.getLogger(NetworkCaptureModule.class);
    private static final ObjectMapper jsonMapper = new ObjectMapper();

    // Enhanced configuration for SAN protocol
    private static final int SAN_PORT = 3260; // Default iSCSI port for SAN
    private static final int SNAPSHOT_LENGTH = 65536;
    private static final int READ_TIMEOUT = 50;

    private PcapNetworkInterface networkInterface;
    private volatile boolean isCapturing = false;
    private ExecutorService executor;
    private PcapHandle handle;

    // Add SAN protocol filter
    private static final String SAN_FILTER = "port " + SAN_PORT;

    public NetworkCaptureModule() throws PcapNativeException {
        listAvailableInterfaces();
        initializeNetworkInterface();
        configureSANFilter();
    }

    private void listAvailableInterfaces() throws PcapNativeException {
        List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();
        if (interfaces.isEmpty()) {
            logger.warn("No network interfaces found");
        } else {
            logger.info("Available network interfaces:");
            for (PcapNetworkInterface pcapNetworkInterface : interfaces) {
                logger.info("Name: {}, Description: {}", pcapNetworkInterface.getName(), pcapNetworkInterface.getDescription());
            }
        }
    }

    private void initializeNetworkInterface() throws PcapNativeException {
        List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();
        if (interfaces.isEmpty()) {
            throw new PcapNativeException("No network interface found");
        }

        // Prioritize virtual interfaces for Cisco environment
        this.networkInterface = interfaces.stream()
                .filter(inter -> inter.getName().startsWith("veth") ||
                        inter.getName().startsWith("bridge") ||
                        inter.getName().equals("en0"))
                .findFirst()
                .orElse(interfaces.get(0));

        logger.info("Selected interface: {} for SAN protocol capture", networkInterface.getName());
    }

    private void configureSANFilter() throws PcapNativeException {
        try {
            if (handle != null) {
                handle.setFilter(SAN_FILTER, BpfProgram.BpfCompileMode.OPTIMIZE);
                logger.info("SAN protocol filter configured successfully");
            }
        } catch (NotOpenException e) {
            logger.error("Error configuring SAN filter", e);
        }
    }

    public void startCapture() {
        if (isCapturing) {
            logger.warn("Capture already in progress");
            return;
        }

        try {
            handle = networkInterface.openLive(
                    SNAPSHOT_LENGTH,
                    PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
                    READ_TIMEOUT);

            configureSANFilter();

            executor = Executors.newSingleThreadExecutor();
            isCapturing = true;

            executor.submit(this::captureAndProcessPackets);
            logger.info("Started capturing SAN protocol packets on interface {}", networkInterface.getName());
        } catch (Exception e) {
            logger.error("Failed to start capture", e);
        }
    }

    private void captureAndProcessPackets() {
        try {
            while (isCapturing) {
                Packet packet = handle.getNextPacket();
                if (packet != null) {
                    processPacketToJson(packet);
                }
                Thread.sleep(10);
            }
        } catch (Exception e) {
            logger.error("Error in packet capture loop", e);
        } finally {
            stopCapture();
        }
    }

    private void processPacketToJson(Packet packet) {
        try {
            // Convert packet to JSON format
            Map<String, Object> packetData = new HashMap<>();
            packetData.put("timestamp", System.currentTimeMillis());
            packetData.put("length", packet.length());
            packetData.put("protocol", packet.getClass().getSimpleName());

            // Extract IP-specific headers
            IpPacket ipPacket = packet.get(IpPacket.class);
            if (ipPacket != null) {
                Map<String, Object> headers = new HashMap<>();
                headers.put("source", ipPacket.getHeader().getSrcAddr().toString());
                headers.put("destination", ipPacket.getHeader().getDstAddr().toString());
                headers.put("type", ipPacket.getHeader().getProtocol().name());
                packetData.put("headers", headers);
            }

            // Convert to JSON string
            String jsonPacket = jsonMapper.writeValueAsString(packetData);
            logger.info("Captured packet: {}", jsonPacket);

            // Here you can add your custom processing logic for the JSON data
            // For example, sending to a message queue or storage system

        } catch (Exception e) {
            logger.error("Error processing packet to JSON", e);
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
}