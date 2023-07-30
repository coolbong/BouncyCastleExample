package io.github.coolbong;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

import static io.github.coolbong.Util.*;
import static junit.framework.TestCase.assertEquals;

public class AesTest {

    static byte[] aes_128bit_16byte = "ABCDEFGHIJKLMNOP".getBytes(StandardCharsets.UTF_8);
    static byte[] aes_192bit_24byte = "ABCDEFGHIJKLMNOPQRSTUVWX".getBytes(StandardCharsets.UTF_8);
    static byte[] aes_256bit_32byte = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef".getBytes(StandardCharsets.UTF_8);


    @Test
    public void aes_ecb_128_encrypt() throws InvalidCipherTextException {
        Aes aes = new Aes();

        byte[] text = "jetbrainintellij".getBytes(StandardCharsets.UTF_8);
        byte[] ret = aes.aesEcbEncrypt(aes_128bit_16byte,text);

        assertEquals("3D17A921520E975F22BD902EAB28E8BC", toHex(ret));
    }

    @Test
    public void aes_ecb_128_decypt() throws InvalidCipherTextException {
        Aes aes = new Aes();
        byte[] text = {
                (byte)0x3d, (byte)0x17, (byte)0xa9, (byte)0x21,
                (byte)0x52, (byte)0x0e, (byte)0x97, (byte)0x5f,
                (byte)0x22, (byte)0xbd, (byte)0x90, (byte)0x2e,
                (byte)0xab, (byte)0x28, (byte)0xe8, (byte)0xbc

        };
        byte[] ret = aes.aesEcbDectypt(aes_128bit_16byte, text);
        assertEquals("jetbrainintellij", new String(ret, StandardCharsets.UTF_8));
    }
}
