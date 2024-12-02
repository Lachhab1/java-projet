# Utiliser une image de base avec Java et Maven
FROM maven:3.8.4-openjdk-17-slim AS build

# Définir le répertoire de travail
WORKDIR /app

# Copier les fichiers de configuration Maven
COPY pom.xml .

# Télécharger les dépendances Maven
RUN mvn dependency:go-offline

# Copier les sources
COPY src ./src

# Compiler l'application
RUN mvn clean package -DskipTests

# Image finale
FROM openjdk:17-slim

# Installer libpcap pour Pcap4J
RUN apt-get update && apt-get install -y libpcap0.8

# Copier l'application construite
COPY --from=build /app/target/network-intrusion-detector-1.0-SNAPSHOT.jar /app/network-intrusion-detector.jar

# Définir les permissions et l'utilisateur
RUN addgroup --system javauser && adduser --system --ingroup javauser javauser
USER javauser

# Point d'entrée
ENTRYPOINT ["java", "-jar", "/app/network-intrusion-detector.jar"]