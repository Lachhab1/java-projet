package com.networkDetector;

import com.networkDetector.capture.NetworkInterfaceHandler;
import com.networkDetector.capture.PacketCaptureManager;
import com.networkDetector.logging.NetworkLogger;
import com.networkDetector.storage.PacketStorageManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class NetworkIntrusionDetector {
    private static final Logger logger = LoggerFactory.getLogger(NetworkIntrusionDetector.class);

    private final PacketCaptureManager captureManager;
    private final NetworkLogger networkLogger;
    private final PacketStorageManager storageManager;

    public NetworkIntrusionDetector() {
        this.networkLogger = new NetworkLogger();
        this.storageManager = new PacketStorageManager();
        NetworkInterfaceHandler interfaceHandler = new NetworkInterfaceHandler();
        this.captureManager = new PacketCaptureManager(interfaceHandler, networkLogger, storageManager);
    }

    public void start() {
        logger.info("Démarrage du détecteur d'intrusion réseau");
        captureManager.startCapture();
    }

    public void stop() {
        logger.info("Arrêt du détecteur d'intrusion réseau");
        captureManager.stopCapture();
    }

    public static void main(String[] args) {
        NetworkIntrusionDetector detector = new NetworkIntrusionDetector();

        // Gestion de l'arrêt propre
        Runtime.getRuntime().addShutdownHook(new Thread(detector::stop));

        detector.start();
    }
}