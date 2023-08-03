package io.github.coolbong;

import javax.xml.bind.DatatypeConverter;
import java.math.BigInteger;

public class Util {

    public static String toHex(byte[] arr) {

        StringBuilder sb = new StringBuilder();
        for (byte b : arr) {
            sb.append(String.format("%02X", b));
        }

        return sb.toString();
    }

    public static String toHex(byte[] arr, String delim) {
        StringBuilder sb = new StringBuilder();
        for (byte b : arr) {
            sb.append(String.format("%02X%s", b, delim));
        }
        sb.deleteCharAt(sb.length() - 1);

        return sb.toString();
    }



    public static String to_bytes_variable(byte[] arr) {

        StringBuilder sb = new StringBuilder();
        for (byte b : arr) {
            sb.append(String.format("(byte)0x%02x, ", b));
        }
        sb.deleteCharAt(sb.length() - 1);
        sb.deleteCharAt(sb.length() - 1);

        return sb.toString();
    }

    public static void print(byte[] arr) {
        StringBuilder sb = new StringBuilder();
        for (byte b : arr) {
            sb.append(String.format("%02X:", b));
        }
        sb.deleteCharAt(sb.length() - 1);
        System.out.println(sb);
    }

    public static byte[] toBytes(String hex) {
        //BigInteger bi = new BigInteger(hex, 16);
        //return bi.toByteArray();
//        int len = hex.length();
//        byte[] data = new byte[len / 2];
//        for (int i = 0; i < len; i += 2) {
//            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
//                    + Character.digit(hex.charAt(i+1), 16));
//        }
        //return data;
        return DatatypeConverter.parseHexBinary(hex);
    }
}
