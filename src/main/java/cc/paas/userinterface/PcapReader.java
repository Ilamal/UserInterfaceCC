package cc.paas.userinterface;

// Author Kevin

import org.apache.commons.codec.binary.Hex;
import org.pcap4j.core.*;

import org.pcap4j.packet.Packet;

import java.io.EOFException;
import java.util.HashMap;
import java.util.concurrent.TimeoutException;

public class PcapReader {


    public static HashMap<String, Object> pcapReader(String path) {
        System.out.println(System.getProperty("user.dir")); //to get the root path of
        HashMap<String, Object> data = new HashMap<>();
        boolean isSSIDset = false;
        //
        PcapHandle handle;
        try {
            handle = Pcaps.openOffline(path);
            for (int i = 0; i <= 60; i++) { //size of packet length check in Wireshark.

                Packet packet = handle.getNextPacketEx();
                int length = packet.length();
                if (isSSIDset && (length == 209)) {
                    continue;
                }
                byte[] packetInByte = packet.getRawData();
                switch (length) {
                    case 133:
                        if (packetInByte[1] == 2) {
                            stateOne(data, packetInByte);
                        }
                        break;
                    case 155:
                        stateTwo(data, packetInByte);
                        break;
                    case 189:
                        break;
                    case 209:

                        getSSID(data, packetInByte);
                        isSSIDset = true;
                        break;
                }
            }
            handle.close();
        } catch (PcapNativeException e) {
            e.printStackTrace();
        } catch (NotOpenException e) {
            e.printStackTrace();
        } catch (EOFException e) {
            e.printStackTrace();
        } catch (TimeoutException e) {
            e.printStackTrace();
        }

        return data;

    }

    private static void stateOne(HashMap<String, Object> data, byte[] byteArray) {
        byte[] clientMac = new byte[6];
        byte[] bssid = new byte[6];
        byte[] aNonce = new byte[32];
        //version = 1 byte postion 34
        int version = byteArray[34];
        //mac and magic numbers from pcap
        System.arraycopy(byteArray, 4, clientMac, 0, 6);
        System.arraycopy(byteArray, 10, bssid, 0, 6);
        //nonce starting at 51xOffset size 32byte
        System.arraycopy(byteArray, 51, aNonce, 0, 32);

        data.put("clientMac", Hex.encodeHexString( clientMac));
        data.put("bssid", Hex.encodeHexString(bssid));
        data.put("aNonce", Hex.encodeHexString( aNonce));
        data.put("version", version);
    }

    private static void stateTwo(HashMap<String, Object> data, byte[] byteArray)  {
        byte[] sNonce = new byte[32];
        byte[] mic = new byte[16];
        byte[] auth= new byte[121];

        System.arraycopy(byteArray,34,auth,0,121);
        data.put("auth",Hex.encodeHexString(auth));
        //nonce starting at 51xOffset size 32byte
        System.arraycopy(byteArray, 51, sNonce, 0, 32);
        System.arraycopy(byteArray, 115, mic, 0, 16);
        System.out.println("here");
        data.put("sNonce", Hex.encodeHexString(sNonce));
        data.put("mic",  Hex.encodeHexString(mic));
    }

    //ssid on Position
    private static void getSSID(HashMap<String, Object> data, byte[] byteArray) {


        StringBuilder builder = new StringBuilder();
        String ssid;


        int size = byteArray[37];
        //starting with the 2. byte because first one is indecator how big
        for (int i = 0; i < size; i++) {

            char c = (char) byteArray[38 + i];
            builder.append(c);
        }
        ssid = builder.toString();
        data.put("ssid", ssid);

    }

}

