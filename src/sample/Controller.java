package sample;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Tab;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.layout.StackPane;
import jpcap.packet.Packet;

import java.net.URL;
import java.util.ResourceBundle;

public class Controller implements Initializable {

    private Packet packet;

    @FXML
    private StackPane container;
    @FXML
    private ComboBox<String> selectNetworkCard = new ComboBox<>();
    @FXML
    private ComboBox<String> selectProtocol = new ComboBox<>();
    @FXML
    private TableView<Package> packetTable = new TableView<>();
    @FXML
    private TableColumn<Packet,Integer> No_col = new TableColumn<>();
    @FXML
    private TableColumn<Packet,Double> time_col = new TableColumn<>();
    @FXML
    private TableColumn<Packet,String> source_col = new TableColumn<>();
    @FXML
    private TableColumn<Packet,String> target_col = new TableColumn<>();
    @FXML
    private TableColumn<Packet,String> protocol_col = new TableColumn<>();
    @FXML
    private TableColumn<Packet,Integer> length_col = new TableColumn<>();
    @FXML
    private TableColumn<Packet,String> info_col = new TableColumn<>();


    public static ObservableList<Packet> packets = FXCollections.observableArrayList();

    @Override
    public void initialize(URL location, ResourceBundle resources) {

    }
}
