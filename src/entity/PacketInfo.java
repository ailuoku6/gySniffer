package entity;

import jpcap.packet.Packet;

public class PacketInfo {
    private Integer no;
    private String time;
    private String sourceIp;
    private String targetIp;
    private String protocol;
    private Integer length;
    private String info;
    private Packet packet;
    private String interfaceName;

    public PacketInfo(Integer no, String time, String sourceIp, String targetIp, String protocol, Integer length, String info,Packet packet) {
        this.no = no;
        this.time = time;
        this.sourceIp = sourceIp;
        this.targetIp = targetIp;
        this.protocol = protocol;
        this.length = length;
        this.info = info;
        this.packet = packet;
    }

    public PacketInfo(Integer no, String time, String sourceIp, String targetIp, String protocol, Integer length, String info) {
        this.no = no;
        this.time = time;
        this.sourceIp = sourceIp;
        this.targetIp = targetIp;
        this.protocol = protocol;
        this.length = length;
        this.info = info;
    }

    public PacketInfo() {
    }

    public Integer getNo() {
        return no;
    }

    public void setNo(Integer no) {
        this.no = no;
    }

    public String getTime() {
        return time;
    }

    public void setTime(String time) {
        this.time = time;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public void setSourceIp(String sourceIp) {
        this.sourceIp = sourceIp;
    }

    public String getTargetIp() {
        return targetIp;
    }

    public void setTargetIp(String targetIp) {
        this.targetIp = targetIp;
    }

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public Integer getLength() {
        return length;
    }

    public void setLength(Integer length) {
        this.length = length;
    }

    public String getInfo() {
        return info;
    }

    public void setInfo(String info) {
        this.info = info;
    }

    public Packet getPacket() {
        return packet;
    }

    public void setPacket(Packet packet) {
        this.packet = packet;
    }

    public String getInterfaceName() {
        return interfaceName;
    }

    public void setInterfaceName(String interfaceName) {
        this.interfaceName = interfaceName;
    }
}
