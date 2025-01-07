package com.networkDetector.protocol.analyzer;

import com.networkDetector.protocol.model.ProtocolType;
import com.networkDetector.protocol.model.ThreatInfo;
import com.networkDetector.protocol.model.ThreatLevel;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.namednumber.TcpPort;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ThreatDetectorTest {

    private final ThreatDetector threatDetector = new ThreatDetector();

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

        ThreatInfo threatInfo = threatDetector.detectThreat(packet, ProtocolType.HTTPS);
        assertEquals(ThreatLevel.HIGH, threatInfo.getThreatLevel());
        assertEquals("SQL injection detected", threatInfo.getThreatType());
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

        ThreatInfo threatInfo = threatDetector.detectThreat(packet, ProtocolType.FTP);
        assertEquals(ThreatLevel.MEDIUM, threatInfo.getThreatLevel());
        assertEquals("Suspicious FTP command detected", threatInfo.getThreatType());
    }
}