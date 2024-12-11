package com.networkDetector.storage;

import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ConcurrentLinkedQueue;

public class PacketStorageManager {
    private static final Logger logger = LoggerFactory.getLogger(PacketStorageManager.class);
    private static final int MAX_STORAGE_SIZE = 1000;

    private final ConcurrentLinkedQueue<Packet> packetQueue = new ConcurrentLinkedQueue<>();

    public void storePacket(Packet packet) {
        if (packetQueue.size() >= MAX_STORAGE_SIZE) {
            packetQueue.poll(); // Remove oldest packet if queue is full
        }
        packetQueue.offer(packet);
    }

    public void clearStorage() {
        packetQueue.clear();
        logger.info("Stockage des paquets effacé");
    }

    public ConcurrentLinkedQueue<Packet> getStoredPackets() {
        return new ConcurrentLinkedQueue<>(packetQueue);
    }
}
