package sample;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

import java.lang.reflect.Array;
import java.util.ArrayList;

public class Main extends Application {

    @Override
    public void start(Stage primaryStage) throws Exception{
//        System.out.println(System.getProperty("java.library.path"));
//        ArrayList<PcapIf> alldevs = new ArrayList<>();
//        StringBuilder errbuf = new StringBuilder();
//        int r = Pcap.findAllDevs(alldevs,errbuf);
//        System.out.println(r==Pcap.NOT_OK);
//        System.out.println(alldevs.size());
        Parent root = FXMLLoader.load(getClass().getResource("sample.fxml"));
        primaryStage.setTitle("GY网络嗅探器");
        primaryStage.setScene(new Scene(root, 1360, 650));
        primaryStage.show();
    }


    public static void main(String[] args) {
        launch(args);
    }
}
