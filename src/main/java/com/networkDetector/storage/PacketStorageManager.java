package com.networkDetector.storage;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.stream.Collectors;

public class PacketStorageManager {
    private static final Logger logger = LoggerFactory.getLogger(PacketStorageManager.class);
    private final ConcurrentLinkedQueue<PacketDTO> packetQueue = new ConcurrentLinkedQueue<>();

    public void storePacket(PacketDTO packetDTO) {
        try {
            packetQueue.add(packetDTO);
            logger.info("Stored packet JSON: {}", packetDTO);
        } catch (Exception e) {
            logger.error("Error storing packet: {}", e.getMessage());
        }
    }

    public List<PacketDTO> getCapturedPackets() {
        try {
            return packetQueue.stream()
                    .collect(Collectors.toList());
        } catch (Exception e) {
            logger.error("Error getting captured packets: {}", e.getMessage());
            return List.of(); // Return an empty list in case of error
        }
    }

    // get total number of packets stored
    public int getTotalPackets() {
        return packetQueue.size();
    }

    // get average packet size
    public double getAveragePacketSize() {
        return packetQueue.stream()
                .mapToLong(PacketDTO::getLength)
                .average()
                .orElse(0.0);
    }
    public void clearCapturedData() {
        packetQueue.clear();
    }

}