package pcap;

import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;

public class NetCard {
    public static NetworkInterface[] getDevices(){
        return JpcapCaptor.getDeviceList();
    }
}
