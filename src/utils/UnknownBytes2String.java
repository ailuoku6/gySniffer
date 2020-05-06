package utils;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;

public class UnknownBytes2String {
    public static String parse(byte[] bytes) throws UnsupportedEncodingException {
        String charset = null;
        if (isUtf8(bytes)){
            charset = "UTF-8";
        }else {
            charset = "gb2312";
        }

        return new String(bytes,charset);
    }

    public static boolean isUtf8(byte[] b){
//        byte[] b = buffer.array();
        boolean beUTF8 = false;
        int nLen = b.length;

        // One chinese charactor is three bytes in utf-8,
        // so bytes less than 3 do not contain chinese charactor
        if (nLen >= 3) {
            byte U1, U2, U3;
            int nNow = 0;
            while (nNow < nLen) {
                U1 = b[nNow];
                if ((U1 & 0x80) == 0x80) {
                    // One chinese charactor is three bytes in utf-8,
                    // so bytes less than 3 do not contain chinese charactor
                    if (nLen > nNow + 2) {
                        U2 = b[nNow + 1];
                        U3 = b[nNow + 2];
                        // One chinese charactor is three bytes in utf-8,
                        // Higher bits of these three bytes shoule be 0xE0 0xC0
                        // 0xC0
                        if (((U1 & 0xE0) == 0XE0) && ((U2 & 0xC0) == 0x80)
                                && ((U3 & 0xC0) == 0x80)) {
                            // maybe UTF-8
                            beUTF8 = true;
                            nNow = nNow + 3;
                        } else {
                            // not UTF-8
                            beUTF8 = false;
                            break;
                        }
                    } else {
                        // not UTF-8
                        beUTF8 = false;
                        break;
                    }
                } else {
                    // not chinese character
                    nNow++;
                }
            }
        }
        return beUTF8;
    }
}
