package com.networkDetector.model;


import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;

public class FilterConfig {
    // Liste des ports suspects
    public static final Set<Integer> SUSPICIOUS_PORTS = Set.of(
            22,    // SSH (potential brute force)
            23,    // Telnet (insecure)
            445,   // SMB (potential exploit)
            3389,  // RDP (potential remote access attack)
            8080,  // Alternative HTTP (often used for malicious services)
            25,    // SMTP (potential spam)
            1433,  // MSSQL (potential database attack)
            1521   // Oracle DB (potential database attack)
    );

    // Adresses IP suspectes ou interdites
    public static final Set<String> BLOCKED_IPS = new CopyOnWriteArraySet<>(Set.of(
            "127.0.0.1",  // Localhost
            "0.0.0.0"     // Unspecified address
    ));

    // Seuils de détection
    public static final int MAX_CONNECTIONS_PER_IP = 100;
    public static final int PACKET_RATE_THRESHOLD = 50; // paquets/seconde

    // Méthode pour ajouter dynamiquement des IPs bloquées
    public static void blockIP(String ip) {
        BLOCKED_IPS.add(ip);
    }
}
