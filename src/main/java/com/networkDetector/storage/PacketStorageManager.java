package com.networkDetector.storage;

import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ConcurrentLinkedQueue;

public class PacketStorageManager {
    private static final Logger logger = LoggerFactory.getLogger(PacketStorageManager.class);
    private static final int DEFAULT_STORAGE_SIZE = 1000;

    private final int maxStorageSize;
    private final ConcurrentLinkedQueue<Packet> packetQueue;

    public PacketStorageManager() {
        this(DEFAULT_STORAGE_SIZE);
    }

    public PacketStorageManager(int maxStorageSize) {
        this.maxStorageSize = maxStorageSize;
        this.packetQueue = new ConcurrentLinkedQueue<>();
    }

    public void storePacket(Packet packet) {
        if (packetQueue.size() >= maxStorageSize) {
            packetQueue.poll(); // Supprimer le paquet le plus ancien si la limite est atteinte
        }
        packetQueue.offer(packet);
        logger.info("Paquet stocké. Taille actuelle: {}", packetQueue.size());
    }

    public void clearStorage() {
        packetQueue.clear();
        logger.info("Stockage des paquets effacé");
    }

    public ConcurrentLinkedQueue<Packet> getStoredPackets() {
        return new ConcurrentLinkedQueue<>(packetQueue);
    }
}
