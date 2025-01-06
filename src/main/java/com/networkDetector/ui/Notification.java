package com.networkDetector.ui;

import com.networkDetector.protocol.model.ThreatLevel;
import javafx.scene.control.Label;
import javafx.scene.layout.VBox;

public class Notification {
    private final String title;
    private final String message;
    private final ThreatLevel level;

    public Notification(String title, String message, ThreatLevel level) {
        this.title = title;
        this.message = message;
        this.level = level;
    }

    public VBox create() {
        VBox notification = new VBox(5);
        notification.getStyleClass().add("notification");

        String color = switch (level) {
            case HIGH -> "#e74c3c";
            case MEDIUM -> "#f1c40f";
            default -> "#2ecc71";
        };

        notification.setStyle(String.format("-fx-background-color: %s;", color));

        Label titleLabel = new Label(title);
        titleLabel.setStyle("-fx-font-weight: bold; -fx-text-fill: white;");

        Label messageLabel = new Label(message);
        messageLabel.setStyle("-fx-text-fill: white;");

        notification.getChildren().addAll(titleLabel, messageLabel);
        return notification;
    }
}
