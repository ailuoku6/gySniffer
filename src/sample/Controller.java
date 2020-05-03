package sample;

import com.sun.xml.internal.bind.v2.runtime.reflect.Lister;
import entity.PacketInfo;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.input.MouseButton;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.StackPane;
import javafx.util.Callback;
import jpcap.packet.Packet;
import pcap.PacketCapture;

import java.net.URL;
import java.util.ResourceBundle;

public class Controller implements Initializable {

    private Packet packet;

    private PacketCapture capture;

    @FXML
    private StackPane container;
    @FXML
    private ComboBox<String> selectNetworkCard = new ComboBox<>();
    @FXML
    private ComboBox<String> selectProtocol = new ComboBox<>();
    @FXML
    private TextField filterMask;
    @FXML
    private Button filterAction;
    @FXML
    private TableView<PacketInfo> packetTable = new TableView<>();
    @FXML
    private TableColumn<PacketInfo,Integer> No_col = new TableColumn<>();
    @FXML
    private TableColumn<PacketInfo,String> time_col = new TableColumn<>();
    @FXML
    private TableColumn<PacketInfo,String> source_col = new TableColumn<>();
    @FXML
    private TableColumn<PacketInfo,String> target_col = new TableColumn<>();
    @FXML
    private TableColumn<PacketInfo,String> protocol_col = new TableColumn<>();
    @FXML
    private TableColumn<PacketInfo,Integer> length_col = new TableColumn<>();
    @FXML
    private TableColumn<PacketInfo,String> info_col = new TableColumn<>();


    public static ObservableList<PacketInfo> packets = FXCollections.observableArrayList();

    public void initPacketTable(){
        packetTable.prefWidthProperty().bind(container.widthProperty());
        packetTable.prefHeightProperty().bind(container.widthProperty().divide(4.0));
        No_col.prefWidthProperty().bind(packetTable.widthProperty().divide(9.0));
        time_col.prefWidthProperty().bind(packetTable.widthProperty().divide(9.0));
        source_col.prefWidthProperty().bind(packetTable.widthProperty().divide(9.0));
        target_col.prefWidthProperty().bind(packetTable.widthProperty().divide(9.0));
        protocol_col.prefWidthProperty().bind(packetTable.widthProperty().divide(9.0));
        length_col.prefWidthProperty().bind(packetTable.widthProperty().divide(9.0));
        info_col.prefWidthProperty().bind(packetTable.widthProperty().divide(3.0));

        No_col.setCellValueFactory(new PropertyValueFactory<PacketInfo,Integer>("no"));
        time_col.setCellValueFactory(new PropertyValueFactory<PacketInfo,String>("time"));
        source_col.setCellValueFactory(new PropertyValueFactory<PacketInfo,String>("sourceIp"));
        target_col.setCellValueFactory(new PropertyValueFactory<PacketInfo,String>("targetIp"));
        protocol_col.setCellValueFactory(new PropertyValueFactory<PacketInfo,String>("protocol"));
        length_col.setCellValueFactory(new PropertyValueFactory<PacketInfo,Integer>("length"));
        info_col.setCellValueFactory(new PropertyValueFactory<PacketInfo,String>("info"));

        packetTable.setItems(packets);


//        packetTable.setOnMouseClicked(new EventHandler<MouseEvent>() {
//            @Override
//            public void handle(MouseEvent event) {
//                if (event.getButton().equals(MouseButton.PRIMARY)
//                        && event.getClickCount() == 1
//                        && this.getIndex() < packetTable.getItems().size()) {
////                    choosedStream = TableRowControl.this.getItem();//获取点击的对象
////                    choosedIndex=TableRowControl.this.getIndex();//获取点击的index，就是表上的第几项
//                }
//            }
//        });

        packetTable.setRowFactory(new Callback<TableView<PacketInfo>, TableRow<PacketInfo>>() {
            @Override
            public TableRow<PacketInfo> call(TableView<PacketInfo> param) {
                return new TableRowControl();
            }
        });
    }

    class TableRowControl extends TableRow<PacketInfo>{
        public TableRowControl(){
            super();
            this.setOnMouseClicked(new EventHandler<MouseEvent>() {
                @Override
                public void handle(MouseEvent event) {
                    if (event.getButton().equals(MouseButton.PRIMARY)
                            && event.getClickCount() == 1
                            && TableRowControl.this.getIndex() < packetTable.getItems().size()) {
//                        choosedStream = TableRowControl.this.getItem();//获取点击的对象
//                        choosedIndex=TableRowControl.this.getIndex();//获取点击的index，就是表上的第几项

                        System.out.println(TableRowControl.this.getIndex());

                    }
                }
            });
        }
    }

    public void filldata(){
        for (int i = 0;i<10;i++){
            PacketInfo info = new PacketInfo(i+1,String.valueOf(i),String.valueOf(i+100),String.valueOf(i+200),"udp",191,"detail");
            packets.add(info);
        }
    }

    public void initCapture(){
        capture = PacketCapture.getInstance();

    }

    public void initConfigure(){
        //初始化头部几个配置
        filterAction.setOnAction(new EventHandler<ActionEvent>() {
            @Override
            public void handle(ActionEvent event) {
                //过滤
            }
        });
    }

    @Override
    public void initialize(URL location, ResourceBundle resources) {
        initPacketTable();
        filldata();
        initCapture();
        initConfigure();
    }
}

