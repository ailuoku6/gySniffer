package pcap;

import entity.PacketInfo;
import jpcap.packet.*;

import javax.xml.bind.DatatypeConverter;
import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class PacketFactory {
    public static PacketInfo packet2Info(Packet packet,Integer no){
        System.out.println(DatatypeConverter.printHexBinary(packet.data));
        PacketInfo info = null;
        if (packet.getClass().equals(ICMPPacket.class)){
            info = ICMPanalyze(packet);
        }else if (packet.getClass().equals(TCPPacket.class)){
            info = TCPanalyze(packet);
        }else if (packet.getClass().equals(UDPPacket.class)){
            info = UDPanalyze(packet);
        }else if (packet.getClass().equals(ARPPacket.class)){
            info = ARPanalyze(packet);
        }else if (packet.getClass().equals(IPPacket.class)){
            info = IPanalyze(packet);
        }
        if (info!=null) info.setNo(no);
        return info==null?new PacketInfo():info;
    }

    public static PacketInfo IPanalyze(Packet packet){
        PacketInfo info = null;
        if (packet instanceof IPPacket){
            info = new PacketInfo();
            IPPacket ipPacket = (IPPacket) packet;
            info.setProtocol("IP");
            info.setTime(String.valueOf(ipPacket.sec));
            info.setSourceIp(ipPacket.src_ip.toString());
            info.setTargetIp(ipPacket.dst_ip.toString());
            info.setLength((int) ipPacket.length);
            info.setInfo(ipPacket.toString());
            info.setPacket(packet);

            System.out.println(ipPacket.header);
        }
        return info;
    }

    public static PacketInfo ICMPanalyze(Packet packet){
        PacketInfo info = null;
        if (packet instanceof ICMPPacket){
            info = new PacketInfo();
            ICMPPacket icmpPacket = (ICMPPacket) packet;
            info.setProtocol("ICMP");
            info.setTime(String.valueOf(icmpPacket.sec));
            info.setSourceIp(icmpPacket.src_ip.toString());
            info.setTargetIp(icmpPacket.dst_ip.toString());
            info.setLength((int) icmpPacket.length);
            info.setInfo(icmpPacket.toString());
            info.setPacket(packet);

            System.out.println(icmpPacket.header);
        }
        return info;
    }

    public static PacketInfo TCPanalyze(Packet packet){
        PacketInfo info = null;
        if (packet instanceof TCPPacket){
            info = new PacketInfo();
            TCPPacket tcpPacket = (TCPPacket) packet;
            info.setProtocol("TCP");
            info.setTime(String.valueOf(tcpPacket.sec));
            info.setSourceIp(tcpPacket.src_ip.toString());
            info.setTargetIp(tcpPacket.dst_ip.toString());
            info.setLength((int) tcpPacket.length);
            info.setInfo(tcpPacket.toString());
            info.setPacket(packet);

            System.out.println(tcpPacket.header);

            System.out.println(tcpPacket.ack);
            System.out.println(tcpPacket.ack_num);
            System.out.println(tcpPacket.caplen);
            System.out.println(tcpPacket.dst_port);
            System.out.println(tcpPacket.src_port);
            System.out.println(tcpPacket.toString());
        }
        return info;
    }

    public static PacketInfo UDPanalyze(Packet packet){
        PacketInfo info = null;
        if (packet instanceof UDPPacket){
            info = new PacketInfo();
            UDPPacket udpPacket = (UDPPacket) packet;
            info.setProtocol("UDP");
            info.setTime(String.valueOf(udpPacket.sec));
            info.setSourceIp(udpPacket.src_ip.toString());
            info.setTargetIp(udpPacket.dst_ip.toString());
            info.setLength(udpPacket.length);
            info.setInfo(udpPacket.toString());
            info.setPacket(packet);

            System.out.println(DatatypeConverter.printHexBinary(udpPacket.header));
        }
        return info;
    }

    public static PacketInfo ARPanalyze(Packet packet){
        PacketInfo info = null;
        if (packet instanceof ARPPacket){
            info = new PacketInfo();
            ARPPacket arpPacket = (ARPPacket) packet;
            info.setProtocol("ARP");
            info.setTime(String.valueOf(arpPacket.sec));
            info.setSourceIp(DatatypeConverter.printHexBinary(arpPacket.sender_hardaddr));
            info.setTargetIp(DatatypeConverter.printHexBinary(arpPacket.target_hardaddr));
            info.setLength(arpPacket.len);
            info.setInfo(arpPacket.toString());
            info.setPacket(packet);
        }
        return info;
    }

    public static String bytes2Mac(byte[] bytes){
        StringBuilder stringBuilder = new StringBuilder();
        int len = bytes.length;
        for (int i = 0; i < len; i++) {
            stringBuilder.append(String.format("%02x", bytes[i]));
            if (i!=len-1) stringBuilder.append(":");
        }
        return stringBuilder.toString();
    }

    public static String bytes2Str(byte[] bytes){
        StringBuilder stringBuilder = new StringBuilder();
        int len = bytes.length;
        for (byte b:
             bytes) {
            stringBuilder.append(String.format("%02x", b));
        }
        return stringBuilder.toString();
    }

    public static int bytes2Int(byte[] b) {
        int value= 0;
        for(int i=0;i<b.length;i++){
            int n=(b[i]<0?(int)b[i]+256:(int)b[i])<<(8*i);
            value+=n;
        }
        return value;
    }

    public static String bytes2Ip(byte[] bytes){
        StringBuilder stringBuilder = new StringBuilder();
        int len = bytes.length;

        for (int i = 0;i<len;i++){
            byte[] bs = {bytes[i]};
            stringBuilder.append(bytes2Int(bs)+(i==len-1?"":"."));
        }

        return stringBuilder.toString();
    }

    public static Map<String,Object> getPacketDetail(Packet packet){
        Map<String,Object> map = new HashMap<>();

        map.put("time",String.valueOf(packet.sec));
        map.put("dataLength",String.valueOf(packet.header.length));

        byte[] etherHead = Arrays.copyOf(packet.header,14);
        map.put("macTarget",bytes2Mac(Arrays.copyOfRange(etherHead,0,6)));
        map.put("macSocrce",bytes2Mac(Arrays.copyOfRange(etherHead,6,12)));
        byte[] etherprotocol = Arrays.copyOfRange(etherHead,12,14);
        map.put("etherProtocol","0x"+bytes2Str(etherprotocol));


        if (etherprotocol[0]==0x08&&etherprotocol[1]==0x00){
            int ipHeadlen = 20;
            byte[] ipHead = Arrays.copyOfRange(packet.header,14,14+ipHeadlen);
            byte i1 = ipHead[0];
            map.put("ipVersion",String.valueOf(i1>>4));
            map.put("ipHeadLen",String.valueOf((i1&0xF)*4));
            map.put("ipServiceType","0x"+String.format("%02x",ipHead[1]));

            map.put("ipTotalLen",String.valueOf(bytes2Int(Arrays.copyOfRange(ipHead,2,4))));
            map.put("Identification","0x"+bytes2Str(Arrays.copyOfRange(ipHead,4,6)));
            map.put("ipFlags","0x"+bytes2Str(Arrays.copyOfRange(ipHead,6,8)));
            byte i6 = ipHead[6];
            i6&=0x1F;
            byte[] offset = {i6,ipHead[7]};
            map.put("ipOffset",String.valueOf(bytes2Int(offset)));
            map.put("ipTTL",String.valueOf(bytes2Int(Arrays.copyOfRange(ipHead,8,9))));
            map.put("ipProtocol",String.valueOf(bytes2Int(Arrays.copyOfRange(ipHead,9,10))));
            map.put("ipHeaderCheckSum","0x"+bytes2Str(Arrays.copyOfRange(ipHead,10,12)));

            map.put("ipSource",bytes2Ip(Arrays.copyOfRange(ipHead,12,16)));
            map.put("ipDestinatin",bytes2Ip(Arrays.copyOfRange(ipHead,16,20)));

            if (map.get("ipProtocol").equals("6")){//TCP
                byte[] tcpHead = Arrays.copyOfRange(packet.header,34,54);
                map.put("tcpSourcePort",bytes2Int(Arrays.copyOfRange(tcpHead,0,2)));
                map.put("tcpDestinationPort",bytes2Int(Arrays.copyOfRange(tcpHead,2,4)));
                map.put("tcpSequence",bytes2Int(Arrays.copyOfRange(tcpHead,4,8)));
                map.put("tcpAck",bytes2Int(Arrays.copyOfRange(tcpHead,8,12)));
                byte b12 = tcpHead[12];
                byte[] arrb12 = {(byte) (b12>>4)};

                map.put("tcpHeadLen",bytes2Int(arrb12)*4);

                byte[] arrb13 = {(byte) (b12&0x3f),tcpHead[13]};
                map.put("tcpFlags","0x"+bytes2Str(arrb13));

                map.put("tcpWindowSize",bytes2Int(Arrays.copyOfRange(tcpHead,14,16)));
                map.put("tcpCheckSum","0x"+bytes2Str(Arrays.copyOfRange(tcpHead,16,18)));
                map.put("tcpUrgent",bytes2Int(Arrays.copyOfRange(tcpHead,18,20)));

            }else if (map.get("ipProtocol").equals("1")){//icmp
                byte[] icmpHead = Arrays.copyOfRange(packet.header,34,42);
                map.put("icmpType",bytes2Int(Arrays.copyOfRange(icmpHead,0,1)));
                map.put("icmpCode",bytes2Int(Arrays.copyOfRange(icmpHead,1,2)));
                map.put("icmpCheckSum","0x"+bytes2Str(Arrays.copyOfRange(icmpHead,2,4)));
//                map.put("icmpIdenti")

            }else if (map.get("ipProtocol").equals("17")){//udp
                byte[] udpHead = Arrays.copyOfRange(packet.header,34,42);
                map.put("udpSourcePort",bytes2Int(Arrays.copyOfRange(udpHead,0,2)));
                map.put("udpDetinationPort",bytes2Int(Arrays.copyOfRange(udpHead,2,4)));
                map.put("udpDataLen",bytes2Int(Arrays.copyOfRange(udpHead,4,6)));
                map.put("udpCheckSum",bytes2Int(Arrays.copyOfRange(udpHead,6,8)));
            }

        }

        return map;
    }

}
