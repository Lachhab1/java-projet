package com.networkDetector.model;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class NetworkStatistics {
    private final ConcurrentMap<String, Integer> connectionCountByIP = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Long> packetTimestampsByIP = new ConcurrentHashMap<>();

    public void recordConnection(String sourceIP) {
        connectionCountByIP.merge(sourceIP, 1, Integer::sum);
    }

    public boolean isConnectionSuspicious(String sourceIP) {
        return connectionCountByIP.getOrDefault(sourceIP, 0) > FilterConfig.MAX_CONNECTIONS_PER_IP;
    }

    public boolean checkPacketRateExceeded(String sourceIP, long timestamp) {
        long currentTime = System.currentTimeMillis();
        Long lastPacketTime = packetTimestampsByIP.put(sourceIP, currentTime);

        if (lastPacketTime != null) {
            long timeDiff = currentTime - lastPacketTime;
            return timeDiff < 1000 / FilterConfig.PACKET_RATE_THRESHOLD;
        }
        return false;
    }
}
