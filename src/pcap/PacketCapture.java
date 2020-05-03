package pcap;

import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import jpcap.packet.Packet;

import java.io.IOException;
import java.util.ArrayList;

public class PacketCapture implements Runnable {

    private volatile static PacketCapture instance = null;

    private NetworkInterface device;

    private String Filter = "";
    private ArrayList<Packet> packets = new ArrayList<>();

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
    }

    public void bindTable(){

    }

    public void setFilter(String filter) {
        Filter = filter;
    }

    public void clearPackets(){
        packets.clear();
    }

    public void DrawTable(){

    }

    @Override
    public void run() {
        Packet packet;
        try {
            JpcapCaptor captor = JpcapCaptor.openDevice(device,65535,true,20);
            while (true){
                long startTime = System.currentTimeMillis();
                while (startTime+600>=System.currentTimeMillis()){
                    packet = captor.getPacket();
                    if (packet!=null){
                        packets.add(packet);
                        DrawTable();
                    }
                }
                Thread.sleep(1000);
            }
        }catch (IOException | InterruptedException e){
            e.printStackTrace();
        }
    }
}
