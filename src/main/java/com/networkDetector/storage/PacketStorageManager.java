package com.networkDetector.storage;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.stream.Collectors;

public class PacketStorageManager {
    private static final Logger logger = LoggerFactory.getLogger(PacketStorageManager.class);
    private static final int DEFAULT_STORAGE_SIZE = 1000;

    private final int maxStorageSize;
    private final ConcurrentLinkedQueue<PacketDTO> packetQueue;
    private final ObjectMapper objectMapper;

    public PacketStorageManager() {
        this(DEFAULT_STORAGE_SIZE);
    }

    public PacketStorageManager(int maxStorageSize) {
        this.maxStorageSize = maxStorageSize;
        this.packetQueue = new ConcurrentLinkedQueue<>();
        this.objectMapper = new ObjectMapper();
    }

    public void storePacket(Packet packet) {
        try {
            PacketDTO packetDTO = PacketConverter.convertPacket(packet);
            if (packetQueue.size() >= maxStorageSize) {
                packetQueue.poll(); // Remove the oldest packet if the limit is reached
            }
            packetQueue.offer(packetDTO);

//            if (logger.isDebugEnabled()) {
//                logger.debug("Stored packet: {}", packetDTO);
//            }
//
//            if (packetQueue.size() % 100 == 0) {
//                logger.info("Packet queue size: {}", packetQueue.size());
//            }
            // Log each packet as JSON
            String jsonPacket = objectMapper.writeValueAsString(packetDTO);
            logger.info("Stored packet JSON: {}", jsonPacket);
        } catch (Exception e) {
            logger.error("Error storing packet: {}", e.getMessage());
        }
    }

    public List<String> getCapturedPackets() {
        try {
            return packetQueue.stream()
                    .map(packet -> {
                        try {
                            return objectMapper.writeValueAsString(packet);
                        } catch (JsonProcessingException e) {
                            logger.error("Error converting packet to JSON: {}", e.getMessage());
                            return "Error converting packet to JSON";
                        }
                    })
                    .collect(Collectors.toList());
        } catch (Exception e) {
            logger.error("Error getting captured packets: {}", e.getMessage());
            return List.of("Error retrieving packets");
        }
    }

    public int getStoredPacketCount() {
        return packetQueue.size();
    }
}