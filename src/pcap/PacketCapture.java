package pcap;

import entity.PacketInfo;
import javafx.collections.ObservableList;
import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import jpcap.packet.Packet;

import java.io.IOException;
import java.util.ArrayList;

public class PacketCapture implements Runnable {

    private volatile static PacketCapture instance = null;

    private NetworkInterface device;

    private String Filter = "";
    private String protocolType = "";
    private ArrayList<Packet> packets = new ArrayList<>();
    private ObservableList<PacketInfo> packetInfos = null;

    private String[] protocolList = {"ICMP","UDP","TCP","IP"};

    //private JpcapCaptor captor;

    private volatile boolean isRun = true;

//    private final Object lock = new Object();
//
//    private boolean pause = false;

    private PacketCapture(){}

    public static PacketCapture getInstance(){
        if (instance==null){
            synchronized (PacketCapture.class){
                if (instance==null){
                    instance = new PacketCapture();
                }
            }
        }
        return instance;
    }

    public void setDevice(NetworkInterface device) {
        this.device = device;
        //captor.close();
    }

    public void setRun(boolean run) {
        isRun = run;
    }

    //
//    public void pauseThread(){
//        this.pause = true;
//    }
//
//    public void resumeThread(){
//        this.pause = false;
//        synchronized (lock){
//            lock.notify();
//        }
//    }
//
//    void onPause(){
//        synchronized (lock){
//            try {
//                lock.wait();
//            }catch (InterruptedException e){
//                e.printStackTrace();
//            }
//        }
//    }

    public void bindTable(ObservableList<PacketInfo> packetInfos){
        this.packetInfos = packetInfos;
    }

    public void setFilter(String filter) {
        Filter = filter;
        DrawTable();
    }

    public void setProtocolType(String protocolType) {
        this.protocolType = protocolType;
        DrawTable();
    }

    public void clearPackets(){
        packets.clear();
        packetInfos.clear();
    }

    public void DrawTable(){
        if (packetInfos!=null){
            packetInfos.clear();
            for (Packet p: packets) {
                if (isFilter(p)){
                    packetInfos.add(PacketFactory.packet2Info(p,packetInfos.size()+1));
                }
            }
        }
    }

    public void addItem2Table(Packet packet){
        if (packetInfos!=null&&isFilter(packet)){
            packetInfos.add(PacketFactory.packet2Info(packet,packetInfos.size()+1));
        }
    }

    private boolean isFilter(Packet packet){//返回true表示满足过滤条件
        boolean flag = true;
        PacketInfo info = PacketFactory.packet2Info(packet,0);
        if (info==null) return false;
        if (!("".equals(protocolType))){
            if (!(info.getProtocol().contains(protocolType))) flag = false;
        }
        if (!("".equals(Filter))){
            if (Filter.contains("sip")){
                String sip = Filter.substring(4);
                if (!info.getSourceIp().contains(sip)) flag = false;
            }else if (Filter.contains("dip")){
                String dip = Filter.substring(4);
                if (!info.getTargetIp().contains(dip)) flag = false;
            }else if (Filter.contains("keyword")){
                String keyword = Filter.substring(8);
                if (!info.getInfo().contains(keyword)) flag = false;
            }
            for (String p:protocolList) {
                if (Filter.contains(p)){
                    if (!info.getProtocol().equals(p)) flag = false;
                    break;
                }
            }
        }
        return flag;
    }


    @Override
    public void run() {
        Packet packet;
        try {
            JpcapCaptor captor = JpcapCaptor.openDevice(device,65535,true,20);
            while (isRun){
                long startTime = System.currentTimeMillis();
                while (startTime+600>=System.currentTimeMillis()){
                    packet = captor.getPacket();
                    if (packet!=null){
                        packets.add(packet);
                        //DrawTable();
                        addItem2Table(packet);
                    }
                }
                Thread.sleep(1000);
            }
        }catch (IOException | InterruptedException e){
            e.printStackTrace();
        }
    }
}
