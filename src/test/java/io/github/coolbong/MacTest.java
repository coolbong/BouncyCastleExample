package io.github.coolbong;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.Test;


import static io.github.coolbong.Util.*;
import static org.junit.Assert.assertEquals;

public class MacTest {


    @Test
    public void des_mac_001() {
        byte[] key = toBytes("404142434445464748494A4B4C4D4E4F");
        byte[] txt = toBytes("00112233445566778899AABBCCDDEEFF");

        Mac mac = new Mac();
        byte[] ret = mac.desMac(key, txt, null);
        assertEquals("00AF1CBDB79B8EF6", toHex(ret));
    }


    @Test
    public void des_mac_method1_algorithm3_test_001() {
        byte[] key = toBytes("404142434445464748494A4B4C4D4E4F");
        byte[] txt = toBytes("6A6574627261696E696E74656C6C696A");

        Mac mac = new Mac();
        byte[] ret = mac.desMacMethod1Alg3(key, txt, null);
        assertEquals("4632E608EE0F3520", toHex(ret));
    }

    @Test
    public void des_mac_method2_algorithm3_001() {
        byte[] key = toBytes("404142434445464748494A4B4C4D4E4F");
        byte[] txt = toBytes("00112233445566778899AABBCCDDEEFF");

        Mac mac = new Mac();
        byte[] ret = mac.desMacMethod2Alg3(key, txt, null);
        assertEquals("E5047A15E8C98E0B", toHex(ret));
    }

    @Test
    public void aes_cmac_001() {
        byte[] key = toBytes("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B");
        byte[] txt = toBytes("4869205468657265");

        Mac mac = new Mac();
        byte[] ret = mac.aesCmac128(key, txt);
        assertEquals("A962DD30ACD5BFED671C4BB64E8FBE42", toHex(ret));
    }

    @Test
    public void aes_cmac_002() {
        //byte[] key = "ABCDEFGHIJKLMNOP".getBytes(StandardCharsets.UTF_8);
        //byte[] txt = "Hello world".getBytes(StandardCharsets.UTF_8);
        byte[] key = {
                (byte)0x41, (byte)0x42, (byte)0x43, (byte)0x44, (byte)0x45, (byte)0x46, (byte)0x47, (byte)0x48,
                (byte)0x49, (byte)0x4a, (byte)0x4b, (byte)0x4c, (byte)0x4d, (byte)0x4e, (byte)0x4f, (byte)0x50
        };
        byte[] txt = {
                (byte)0x48, (byte)0x65, (byte)0x6c, (byte)0x6c, (byte)0x6f, (byte)0x20, (byte)0x77, (byte)0x6f,
                (byte)0x72, (byte)0x6c, (byte)0x64
        };
        Mac mac = new Mac();
        byte[] ret = mac.aesCmac128(key, txt);
        print(ret);
        assertEquals("7E6F0950FB03F381BA82D350F88B7638", toHex(ret));
    }

    @Test
    public void aes_cmac_003() {
        //byte[] key = "ABCDEFGHIJKLMNOP".getBytes(StandardCharsets.UTF_8);
        //byte[] txt = "Hello world".getBytes(StandardCharsets.UTF_8);
        byte[] key = {
                (byte)0x41, (byte)0x42, (byte)0x43, (byte)0x44, (byte)0x45, (byte)0x46, (byte)0x47, (byte)0x48,
                (byte)0x49, (byte)0x4a, (byte)0x4b, (byte)0x4c, (byte)0x4d, (byte)0x4e, (byte)0x4f, (byte)0x50
        };
        byte[] txt = {
                (byte)0x48, (byte)0x65, (byte)0x6c, (byte)0x6c, (byte)0x6f, (byte)0x20, (byte)0x77, (byte)0x6f,
                (byte)0x72, (byte)0x6c, (byte)0x64
        };
        byte[] iv = new byte[16];
        iv[15] = 0x01;
        Mac mac = new Mac();
        byte[] ret = mac.aesCmac128(key, txt, iv);
        print(ret);
        assertEquals("3E3BA415A237749D9FE43D32D04DBE48", toHex(ret));
    }


    @Test
    public void aes_mac_001() throws InvalidCipherTextException {
        byte[] key = toBytes("404142434445464748494A4B4C4D4E4F");
        //byte[] txt = toBytes("6A6574627261696E696E74656C6C696A");
        byte[] txt = { // jetbrainintellijpasswordoverflow
                (byte)0xf3, (byte)0x18, (byte)0x48, (byte)0xf5, (byte)0x3c, (byte)0xc2, (byte)0xdb, (byte)0xcd,
                (byte)0x77, (byte)0xae, (byte)0x06, (byte)0x8b, (byte)0xa2, (byte)0x24, (byte)0xea, (byte)0xcf,
                (byte)0x57, (byte)0x4e, (byte)0xae, (byte)0x50, (byte)0x75, (byte)0x87, (byte)0xfb, (byte)0xf4,
                (byte)0x9c, (byte)0x8b, (byte)0x6d, (byte)0xdc, (byte)0x4c, (byte)0x27, (byte)0x5a, (byte)0x6e
        };

        Mac mac = new Mac();
        byte[] ret = mac.aesMac(key, txt, null);
        assertEquals("B77F56D608AA9F4C71E33AAC3CD92312", toHex(ret));
    }

    @Test
    public void aes_mac_002() throws InvalidCipherTextException {
        byte[] key = toBytes("404142434445464748494A4B4C4D4E4F");
        byte[] txt = { // jetbrainintellijpasswordoverflow
                (byte)0xf3, (byte)0x18, (byte)0x48, (byte)0xf5, (byte)0x3c, (byte)0xc2, (byte)0xdb, (byte)0xcd,
                (byte)0x77, (byte)0xae, (byte)0x06, (byte)0x8b, (byte)0xa2, (byte)0x24, (byte)0xea, (byte)0xcf,
                (byte)0x57, (byte)0x4e, (byte)0xae, (byte)0x50, (byte)0x75, (byte)0x87, (byte)0xfb, (byte)0xf4,
                (byte)0x9c, (byte)0x8b, (byte)0x6d, (byte)0xdc, (byte)0x4c, (byte)0x27, (byte)0x5a, (byte)0x6e
        };
        byte[] iv = {
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01
        };

        Mac mac = new Mac();
        byte[] ret = mac.aesMac(key, txt, iv);
        assertEquals("2CEEB7D09DF73630FCD0F6E60684922C", toHex(ret));
    }

}
