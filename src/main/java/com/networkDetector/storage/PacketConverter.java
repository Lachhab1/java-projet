package com.networkDetector.storage;

import org.pcap4j.packet.*;
import org.pcap4j.util.MacAddress;

import java.time.Instant;
import java.util.Optional;

public class PacketConverter {

    public static PacketDTO convertPacket(Packet packet) {
        String sourceAddress = null;
        String destAddress = null;
        Integer sourcePort = null;
        Integer destPort = null;
        String protocol = "UNKNOWN";

        // Extract IP packet information
        Optional<IpV4Packet> ipV4PacketOptional = Optional.ofNullable(packet.get(IpV4Packet.class));
        if (ipV4PacketOptional.isPresent()) {
            IpV4Packet ipV4Packet = ipV4PacketOptional.get();
            IpV4Packet.IpV4Header ipV4Header = ipV4Packet.getHeader();
            sourceAddress = ipV4Header.getSrcAddr().getHostAddress();
            destAddress = ipV4Header.getDstAddr().getHostAddress();
            protocol = ipV4Header.getProtocol().name();
        }

        // Extract TCP information
        Optional<TcpPacket> tcpPacketOptional = Optional.ofNullable(packet.get(TcpPacket.class));
        if (tcpPacketOptional.isPresent()) {
            TcpPacket tcpPacket = tcpPacketOptional.get();
            TcpPacket.TcpHeader tcpHeader = tcpPacket.getHeader();
            sourcePort = tcpHeader.getSrcPort().valueAsInt();
            destPort = tcpHeader.getDstPort().valueAsInt();
            protocol = "TCP";
        }

        // Extract UDP information
        Optional<UdpPacket> udpPacketOptional = Optional.ofNullable(packet.get(UdpPacket.class));
        if (udpPacketOptional.isPresent()) {
            UdpPacket udpPacket = udpPacketOptional.get();
            UdpPacket.UdpHeader udpHeader = udpPacket.getHeader();
            sourcePort = udpHeader.getSrcPort().valueAsInt();
            destPort = udpHeader.getDstPort().valueAsInt();
            protocol = "UDP";
        }

        // If we couldn't get IP addresses, try to get MAC addresses
        if (sourceAddress == null) {
            Optional<EthernetPacket> ethernetPacketOptional = Optional.ofNullable(packet.get(EthernetPacket.class));
            if (ethernetPacketOptional.isPresent()) {
                EthernetPacket ethernetPacket = ethernetPacketOptional.get();
                EthernetPacket.EthernetHeader ethernetHeader = ethernetPacket.getHeader();
                sourceAddress = ethernetHeader.getSrcAddr().toString();
                destAddress = ethernetHeader.getDstAddr().toString();
                protocol = "ETHERNET";
            }
        }

        return new PacketDTO(
                Instant.now().toString(),
                protocol,
                sourceAddress != null ? sourceAddress : "unknown",
                destAddress != null ? destAddress : "unknown",
                sourcePort,
                destPort,
                (long) packet.length(),
                packet.getClass().getSimpleName(),
                packet.getRawData().toString());
    }
}