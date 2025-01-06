package com.networkDetector.protocol.analyzer;

import com.networkDetector.protocol.model.ProtocolType;
import com.networkDetector.protocol.model.ThreatLevel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.namednumber.TcpPort;
import org.pcap4j.packet.namednumber.UdpPort;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ThreatDetectorTest {

    private ThreatDetector threatDetector;

    @BeforeEach
    public void setUp() {
        threatDetector = new ThreatDetector();
    }

    @Test
    public void testDetectHttpsThreat() {
        // Mock a TCP packet with HTTPS port and SQL injection payload
        TcpPacket tcpPacket = mock(TcpPacket.class);
        TcpPacket.TcpHeader tcpHeader = mock(TcpPacket.TcpHeader.class);
        when(tcpHeader.getDstPort()).thenReturn(TcpPort.HTTPS);
        when(tcpPacket.getHeader()).thenReturn(tcpHeader);
        Packet payload = mock(Packet.class);
        when(payload.getRawData()).thenReturn("SELECT * FROM users".getBytes());
        when(tcpPacket.getPayload()).thenReturn(payload);

        Packet packet = mock(Packet.class);
        when(packet.get(TcpPacket.class)).thenReturn(tcpPacket);

        ThreatLevel threatLevel = threatDetector.detectThreat(packet, ProtocolType.HTTPS);
        assertEquals(ThreatLevel.HIGH, threatLevel);
    }

    @Test
    public void testDetectFtpThreat() {
        // Mock a TCP packet with FTP port and suspicious FTP command
        TcpPacket tcpPacket = mock(TcpPacket.class);
        TcpPacket.TcpHeader tcpHeader = mock(TcpPacket.TcpHeader.class);
        when(tcpHeader.getDstPort()).thenReturn(TcpPort.FTP);
        when(tcpPacket.getHeader()).thenReturn(tcpHeader);
        Packet payload = mock(Packet.class);
        when(payload.getRawData()).thenReturn("USER anonymous".getBytes());
        when(tcpPacket.getPayload()).thenReturn(payload);

        Packet packet = mock(Packet.class);
        when(packet.get(TcpPacket.class)).thenReturn(tcpPacket);

        ThreatLevel threatLevel = threatDetector.detectThreat(packet, ProtocolType.FTP);
        assertEquals(ThreatLevel.MEDIUM, threatLevel);
    }

    @Test
    public void testDetectDnsThreat() {
        // Mock a UDP packet with DNS port and large payload
        UdpPacket udpPacket = mock(UdpPacket.class);
        UdpPacket.UdpHeader udpHeader = mock(UdpPacket.UdpHeader.class);
        when(udpHeader.getDstPort()).thenReturn(UdpPort.DOMAIN);
        when(udpPacket.getHeader()).thenReturn(udpHeader);
        Packet payload = mock(Packet.class);
        when(payload.getRawData()).thenReturn(new byte[600]);
        when(udpPacket.getPayload()).thenReturn(payload);

        Packet packet = mock(Packet.class);
        when(packet.get(UdpPacket.class)).thenReturn(udpPacket);

        ThreatLevel threatLevel = threatDetector.detectThreat(packet, ProtocolType.DNS);
        assertEquals(ThreatLevel.HIGH, threatLevel);
    }

    @Test
    public void testDetectLowThreat() {
        // Mock a TCP packet with non-HTTPS/FTP port
        TcpPacket tcpPacket = mock(TcpPacket.class);
        TcpPacket.TcpHeader tcpHeader = mock(TcpPacket.TcpHeader.class);
        when(tcpHeader.getDstPort()).thenReturn(TcpPort.HTTP);
        when(tcpPacket.getHeader()).thenReturn(tcpHeader);

        Packet packet = mock(Packet.class);
        when(packet.get(TcpPacket.class)).thenReturn(tcpPacket);

        ThreatLevel threatLevel = threatDetector.detectThreat(packet, ProtocolType.HTTP);
        assertEquals(ThreatLevel.LOW, threatLevel);
    }
}