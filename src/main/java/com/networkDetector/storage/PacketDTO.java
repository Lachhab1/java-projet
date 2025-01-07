// PacketDTO.java
package com.networkDetector.storage;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

public class PacketDTO {
    private final String timestamp;
    private final String protocol;
    private final String sourceAddress;
    private final String destinationAddress;
    private final Integer sourcePort;
    private final Integer destinationPort;
    private final Long length;
    private final String packetType;
    private final String payload;

    public PacketDTO(
            @JsonProperty("timestamp") String timestamp,
            @JsonProperty("protocol") String protocol,
            @JsonProperty("sourceAddress") String sourceAddress,
            @JsonProperty("destinationAddress") String destinationAddress,
            @JsonProperty("sourcePort") Integer sourcePort,
            @JsonProperty("destinationPort") Integer destinationPort,
            @JsonProperty("length") Long length,
            @JsonProperty("packetType") String packetType,
            @JsonProperty("payload") String payload) {
        this.timestamp = timestamp;
        this.protocol = protocol;
        this.sourceAddress = sourceAddress;
        this.destinationAddress = destinationAddress;
        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
        this.length = length;
        this.packetType = packetType;
        this.payload = payload;
    }

    // Getters
    public String getTimestamp() {
        return timestamp;
    }

    public String getProtocol() {
        return protocol;
    }

    public String getSourceAddress() {
        return sourceAddress;
    }

    public String getDestinationAddress() {
        return destinationAddress;
    }

    public Integer getSourcePort() {
        return sourcePort;
    }

    public Integer getDestinationPort() {
        return destinationPort;
    }

    public Long getLength() {
        return length;
    }

    public String getPacketType() {
        return packetType;
    }

    public String getPayload() {
        return payload;
    }

    // get size of packet
    public int getSize() {
        return length.intValue();
    }

    // get packet type
    public String getPacketType(Packet packet) {
        if (packet instanceof TcpPacket) {
            return "TCP";
        } else if (packet instanceof UdpPacket) {
            return "UDP";
        } else if (packet instanceof IpV4Packet) {
            return "IPV4";
        } else {
            return "UNKNOWN";
        }
    }

    @Override
    public String toString() {
        return String.format("[%s] %s:%d -> %s:%d (%s)",
                timestamp, sourceAddress, sourcePort,
                destinationAddress, destinationPort, protocol);
    }
}