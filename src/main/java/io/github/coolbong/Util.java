package io.github.coolbong;

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
}
