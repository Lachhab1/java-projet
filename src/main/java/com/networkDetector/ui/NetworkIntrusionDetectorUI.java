package com.networkDetector.ui;

import com.networkDetector.NetworkIntrusionDetector;
import com.networkDetector.storage.PacketDTO;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.chart.LineChart;
import javafx.scene.chart.NumberAxis;
import javafx.scene.chart.XYChart;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.Stage;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.scene.chart.PieChart;
import javafx.scene.control.cell.PropertyValueFactory;
import java.util.concurrent.atomic.AtomicInteger;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNativeException;
import java.util.List;

public class NetworkIntrusionDetectorUI extends Application {
    private NetworkIntrusionDetector detector;
    private TextArea packetTextArea;
    private Label statsLabel;
    private TableView<PacketDTO> packetTable; // Updated to use PacketDTO
    private LineChart<Number, Number> trafficChart;
    private PieChart protocolChart;
    private XYChart.Series<Number, Number> trafficSeries;
    private AtomicInteger xSeriesData = new AtomicInteger(0);
    private Label statusLabel;
    private ComboBox<NetworkInterfaceItem> interfaceSelector;

    private static class NetworkInterfaceItem {
        private final PcapNetworkInterface networkInterface;

        public NetworkInterfaceItem(PcapNetworkInterface networkInterface) {
            this.networkInterface = networkInterface;
        }

        @Override
        public String toString() {
            return networkInterface.getName() + " - " +
                    (networkInterface.getDescription() != null ? networkInterface.getDescription() : "No description");
        }

        public PcapNetworkInterface getNetworkInterface() {
            return networkInterface;
        }
    }

    @Override
    public void start(Stage primaryStage) {
        try {
            detector = new NetworkIntrusionDetector();
            BorderPane mainLayout = new BorderPane();
            mainLayout.setPadding(new Insets(10));

            // Top Control Panel
            HBox controlPanel = createControlPanel();
            mainLayout.setTop(controlPanel);

            // Center Content
            TabPane tabPane = new TabPane();

            // Live Packets Tab
            Tab livePacketsTab = new Tab("Live Packets", createPacketMonitorPane());
            livePacketsTab.setClosable(false);

            // Statistics Tab
            Tab statisticsTab = new Tab("Statistics", createStatisticsPane());
            statisticsTab.setClosable(false);

            // Alerts Tab
            Tab alertsTab = new Tab("Alerts", createAlertsPane());
            alertsTab.setClosable(false);

            tabPane.getTabs().addAll(livePacketsTab, statisticsTab, alertsTab);
            mainLayout.setCenter(tabPane);

            // Status Bar
            statusLabel = new Label("Ready");
            statusLabel.setPadding(new Insets(5));
            mainLayout.setBottom(statusLabel);

            Scene scene = new Scene(mainLayout, 1200, 800);
            scene.getStylesheets().add(getClass().getResource("/styles.css").toExternalForm());

            primaryStage.setTitle("Network Intrusion Detector");
            primaryStage.setScene(scene);
            primaryStage.show();

            startUIUpdateThread();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void populateInterfaceComboBox() {
        try {
            List<PcapNetworkInterface> interfaces = detector.getAvailableInterfaces();
            ObservableList<NetworkInterfaceItem> interfaceItems = FXCollections.observableArrayList();

            for (PcapNetworkInterface networkInterface : interfaces) {
                interfaceItems.add(new NetworkInterfaceItem(networkInterface));
            }

            interfaceSelector.setItems(interfaceItems);

            if (!interfaceItems.isEmpty()) {
                interfaceSelector.setValue(interfaceItems.get(0));
            }
        } catch (PcapNativeException e) {
            showError("Interface Error", "Failed to get network interfaces: " + e.getMessage());
        }
    }

    private HBox createControlPanel() {
        HBox controlPanel = new HBox(10);
        controlPanel.setPadding(new Insets(10));

        // Initialize interface selector
        interfaceSelector = new ComboBox<>();
        populateInterfaceComboBox();

        Button startButton = new Button("Start Capture");
        startButton.getStyleClass().add("button-success");
        startButton.setOnAction(event -> {
            NetworkInterfaceItem selectedInterface = interfaceSelector.getValue();
            if (selectedInterface == null) {
                showError("No Interface Selected", "Please select a network interface before starting capture.");
                return;
            }

            new Thread(() -> {
                try {
                    detector.startCapture(selectedInterface.getNetworkInterface());

                    Platform.runLater(() -> statusLabel
                            .setText("Capturing packets on " + selectedInterface.getNetworkInterface().getName()));
                } catch (Exception e) {
                    Platform.runLater(() -> showError("Capture Error", e));
                }
            }).start();
        });

        Button stopButton = new Button("Stop Capture");
        stopButton.getStyleClass().add("button-danger");
        stopButton.setOnAction(event -> {
            new Thread(() -> {
                detector.stop();
                Platform.runLater(() -> statusLabel.setText("Capture stopped"));
            }).start();
        });

        Button clearButton = new Button("Clear Data");
        clearButton.setOnAction(event -> clearAllData());

        Button refreshButton = new Button("Refresh Interfaces");
        refreshButton.setOnAction(event -> populateInterfaceComboBox());

        controlPanel.getChildren().addAll(
                new Label("Interface:"),
                interfaceSelector,
                refreshButton,
                startButton,
                stopButton,
                clearButton);

        return controlPanel;
    }

    private VBox createPacketMonitorPane() {
        VBox monitorPane = new VBox(10);
        monitorPane.setPadding(new Insets(10));

        // Packet Table
        packetTable = new TableView<>();

        // Define columns for PacketDTO
        TableColumn<PacketDTO, String> timeCol = new TableColumn<>("Time");
        timeCol.setCellValueFactory(new PropertyValueFactory<>("timestamp"));

        TableColumn<PacketDTO, String> protocolCol = new TableColumn<>("Protocol");
        protocolCol.setCellValueFactory(new PropertyValueFactory<>("protocol"));

        TableColumn<PacketDTO, String> sourceCol = new TableColumn<>("Source");
        sourceCol.setCellValueFactory(new PropertyValueFactory<>("sourceAddress"));

        TableColumn<PacketDTO, String> destCol = new TableColumn<>("Destination");
        destCol.setCellValueFactory(new PropertyValueFactory<>("destinationAddress"));

        TableColumn<PacketDTO, Integer> lengthCol = new TableColumn<>("Length");
        lengthCol.setCellValueFactory(new PropertyValueFactory<>("length"));

        packetTable.getColumns().addAll(timeCol, protocolCol, sourceCol, destCol, lengthCol);

        // Packet Details
        packetTextArea = new TextArea();
        packetTextArea.setEditable(false);
        packetTextArea.setPrefRowCount(10);

        monitorPane.getChildren().addAll(
                new Label("Live Packet Capture"),
                packetTable,
                new Label("Packet Details"),
                packetTextArea);

        return monitorPane;
    }

    private VBox createStatisticsPane() {
        VBox statsPane = new VBox(10);
        statsPane.setPadding(new Insets(10));

        // Traffic Chart
        NumberAxis xAxis = new NumberAxis();
        NumberAxis yAxis = new NumberAxis();
        trafficChart = new LineChart<>(xAxis, yAxis);
        trafficChart.setTitle("Network Traffic");
        trafficSeries = new XYChart.Series<>();
        trafficChart.getData().add(trafficSeries);

        // Protocol Distribution Chart
        protocolChart = new PieChart();
        protocolChart.setTitle("Protocol Distribution");

        // Statistics Labels
        statsLabel = new Label("Capture Statistics");

        GridPane statsGrid = new GridPane();
        statsGrid.setHgap(10);
        statsGrid.setVgap(10);
        statsGrid.addRow(0, new Label("Total Packets:"), new Label("0"));
        statsGrid.addRow(1, new Label("Average Size:"), new Label("0 bytes"));
        statsGrid.addRow(2, new Label("Bandwidth:"), new Label("0 Mbps"));

        statsPane.getChildren().addAll(
                trafficChart,
                protocolChart,
                statsLabel,
                statsGrid);

        return statsPane;
    }

    private VBox createAlertsPane() {
        VBox alertsPane = new VBox(10);
        alertsPane.setPadding(new Insets(10));

        ListView<String> alertsList = new ListView<>();
        alertsList.setItems(FXCollections.observableArrayList(
                "Warning: Unusual traffic pattern detected",
                "Alert: Multiple connection attempts from blocked IP",
                "Info: New device connected to network"));

        alertsPane.getChildren().addAll(
                new Label("Security Alerts"),
                alertsList);

        return alertsPane;
    }

    private void startUIUpdateThread() {
        Thread updateThread = new Thread(() -> {
            while (true) {
                try {
                    Thread.sleep(1000);
                    Platform.runLater(this::updateUI);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        });
        updateThread.setDaemon(true);
        updateThread.start();
    }

    private void updateUI() {
        // Update packet display
        List<PacketDTO> capturedPackets = detector.getCapturedPackets(); // Assuming this returns List<PacketDTO>
        ObservableList<PacketDTO> packetEntries = FXCollections.observableArrayList(capturedPackets);
        packetTable.setItems(packetEntries);

        // Update packet details
        StringBuilder packetBuilder = new StringBuilder();
        for (PacketDTO packet : capturedPackets) {
            packetBuilder.append(packet.toString()).append("\n");
        }
        packetTextArea.setText(packetBuilder.toString());

        // Update statistics
        String stats = detector.getStatistics();
        statsLabel.setText(stats);

        // Update traffic chart
        trafficSeries.getData().add(
                new XYChart.Data<>(xSeriesData.getAndIncrement(), Math.random() * 100));

        // Remove old data points to prevent memory issues
        if (trafficSeries.getData().size() > 50) {
            trafficSeries.getData().remove(0);
        }
    }

    private void clearAllData() {
        packetTextArea.clear();
        packetTable.getItems().clear();
        trafficSeries.getData().clear();
        xSeriesData.set(0);
        statusLabel.setText("Data cleared");
    }

    private void showError(String title, Exception e) {
        showError(title, e.getMessage());
    }

    private void showError(String title, String message) {
        Platform.runLater(() -> {
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setTitle(title);
            alert.setHeaderText(null);
            alert.setContentText(message);
            alert.showAndWait();
        });
    }

    public static void main(String[] args) {
        launch(args);
    }
}