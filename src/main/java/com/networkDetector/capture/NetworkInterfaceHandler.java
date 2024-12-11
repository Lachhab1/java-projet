package com.networkDetector.capture;

import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

public class NetworkInterfaceHandler {
    private static final Logger logger = LoggerFactory.getLogger(NetworkInterfaceHandler.class);

    public PcapNetworkInterface selectDefaultInterface() throws PcapNativeException {
        List<PcapNetworkInterface> devices = Pcaps.findAllDevs();

        if (devices.isEmpty()) {
            throw new PcapNativeException("No network interfaces found");
        }

        // Try to find a non-loopback interface first
        for (PcapNetworkInterface device : devices) {
            if (!device.isLoopBack()) {
                logger.info("Selected network interface: {}", device.getName());
                return device;
            }
        }

        // If no non-loopback interface is found, return the first available interface
        logger.info("Selected loopback interface: {}", devices.get(0).getName());
        return devices.get(0);
    }
}