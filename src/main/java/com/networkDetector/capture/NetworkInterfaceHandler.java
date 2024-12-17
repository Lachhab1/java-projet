package com.networkDetector.capture;

import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

public class NetworkInterfaceHandler {
    private static final Logger logger = LoggerFactory.getLogger(NetworkInterfaceHandler.class);

    private PcapNetworkInterface selectedInterface;

    /**
     * Select the default network interface.
     * Priority: non-loopback interfaces > first available interface.
     */
    public PcapNetworkInterface selectDefaultInterface() throws PcapNativeException {
        List<PcapNetworkInterface> devices = Pcaps.findAllDevs();

        if (devices.isEmpty()) {
            throw new PcapNativeException("No network interfaces found");
        }

        // Try to find a non-loopback interface first
        for (PcapNetworkInterface device : devices) {
            if (!device.isLoopBack()) {
                selectedInterface = device;
                logger.info("Selected network interface: {}", device.getName());
                return selectedInterface;
            }
        }

        // If no non-loopback interface is found, return the first available interface
        selectedInterface = devices.get(0);
        logger.info("Selected loopback interface: {}", selectedInterface.getName());
        return selectedInterface;
    }

    /**
     * List all available network interfaces.
     */
    public List<PcapNetworkInterface> listAllInterfaces() throws PcapNativeException {
        List<PcapNetworkInterface> devices = Pcaps.findAllDevs();

        if (devices.isEmpty()) {
            throw new PcapNativeException("No network interfaces found");
        }

        logger.info("Available network interfaces:");
        for (int i = 0; i < devices.size(); i++) {
            PcapNetworkInterface device = devices.get(i);
            logger.info("{}. {} [{}]", i + 1, device.getName(), device.getDescription());
        }

        return devices;
    }

    /**
     * Select a network interface manually by its name.
     */
    public PcapNetworkInterface selectInterfaceByName(String name) throws PcapNativeException {
        List<PcapNetworkInterface> devices = Pcaps.findAllDevs();

        for (PcapNetworkInterface device : devices) {
            if (device.getName().equals(name)) {
                selectedInterface = device;
                logger.info("Manually selected network interface: {}", device.getName());
                return selectedInterface;
            }
        }

        throw new IllegalArgumentException("No network interface found with the name: " + name);
    }

    /**
     * Select a network interface manually by its index.
     */
    public PcapNetworkInterface selectInterfaceByIndex(int index) throws PcapNativeException {
        List<PcapNetworkInterface> devices = listAllInterfaces();

        if (index < 0 || index >= devices.size()) {
            throw new IndexOutOfBoundsException("Invalid interface index: " + index);
        }

        selectedInterface = devices.get(index);
        logger.info("Manually selected network interface: {}", selectedInterface.getName());
        return selectedInterface;
    }

    /**
     * Get the currently selected network interface.
     */
    public PcapNetworkInterface getSelectedInterface() {
        if (selectedInterface == null) {
            throw new IllegalStateException("No network interface selected yet");
        }

        return selectedInterface;
    }
}
