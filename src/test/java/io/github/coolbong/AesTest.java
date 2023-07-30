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

    static byte[] text = "jetbrainintellijpasswordoverflow".getBytes(StandardCharsets.UTF_8);

    @Test
    public void aes_ecb_256_encrypt() throws InvalidCipherTextException {
        Aes aes = new Aes();
        byte[] ret = aes.aesEcbEncrypt(aes_256bit_32byte,text);
        assertEquals("6F8E0CF5903A79673E8863E47D7E2008E906079ED447DC58E41DDD537508E6D2", toHex(ret));
    }

    @Test
    public void aes_ecb_256_decrypt() throws InvalidCipherTextException {
        Aes aes = new Aes();
        byte[] text = {
                (byte)0x6f, (byte)0x8e, (byte)0x0c, (byte)0xf5, (byte)0x90, (byte)0x3a, (byte)0x79, (byte)0x67,
                (byte)0x3e, (byte)0x88, (byte)0x63, (byte)0xe4, (byte)0x7d, (byte)0x7e, (byte)0x20, (byte)0x08,
                (byte)0xe9, (byte)0x06, (byte)0x07, (byte)0x9e, (byte)0xd4, (byte)0x47, (byte)0xdc, (byte)0x58,
                (byte)0xe4, (byte)0x1d, (byte)0xdd, (byte)0x53, (byte)0x75, (byte)0x08, (byte)0xe6, (byte)0xd2
        };
        byte[] ret = aes.aesEcbDecrypt(aes_256bit_32byte, text);
        assertEquals("jetbrainintellijpasswordoverflow", new String(ret, StandardCharsets.UTF_8));
    }

    @Test
    public void aes_ecb_192_encrypt() throws InvalidCipherTextException {
        Aes aes = new Aes();
        byte[] ret = aes.aesEcbEncrypt(aes_192bit_24byte,text);
        assertEquals("F31848F53CC2DBCD77AE068BA224EACF8AF8FA4A22136027D9E261B2DDDAF6B9", toHex(ret));
    }

    @Test
    public void aes_ecb_192_decrypt() throws InvalidCipherTextException {
        Aes aes = new Aes();
        byte[] text = {
                (byte)0xf3, (byte)0x18, (byte)0x48, (byte)0xf5, (byte)0x3c, (byte)0xc2, (byte)0xdb, (byte)0xcd,
                (byte)0x77, (byte)0xae, (byte)0x06, (byte)0x8b, (byte)0xa2, (byte)0x24, (byte)0xea, (byte)0xcf,
                (byte)0x8a, (byte)0xf8, (byte)0xfa, (byte)0x4a, (byte)0x22, (byte)0x13, (byte)0x60, (byte)0x27,
                (byte)0xd9, (byte)0xe2, (byte)0x61, (byte)0xb2, (byte)0xdd, (byte)0xda, (byte)0xf6, (byte)0xb9
        };
        byte[] ret = aes.aesEcbDecrypt(aes_192bit_24byte, text);
        assertEquals("jetbrainintellijpasswordoverflow", new String(ret, StandardCharsets.UTF_8));
    }

    @Test
    public void aes_ecb_128_encrypt() throws InvalidCipherTextException {
        Aes aes = new Aes();
        byte[] ret = aes.aesEcbEncrypt(aes_128bit_16byte, text);
        assertEquals("3D17A921520E975F22BD902EAB28E8BCA91FC3E8AB5C69F83614A0F31E80877D", toHex(ret));
    }

    @Test
    public void aes_ecb_128_decrypt() throws InvalidCipherTextException {
        Aes aes = new Aes();
        byte[] text = {
                (byte)0x3d, (byte)0x17, (byte)0xa9, (byte)0x21, (byte)0x52, (byte)0x0e, (byte)0x97, (byte)0x5f,
                (byte)0x22, (byte)0xbd, (byte)0x90, (byte)0x2e, (byte)0xab, (byte)0x28, (byte)0xe8, (byte)0xbc,
                (byte)0xa9, (byte)0x1f, (byte)0xc3, (byte)0xe8, (byte)0xab, (byte)0x5c, (byte)0x69, (byte)0xf8,
                (byte)0x36, (byte)0x14, (byte)0xa0, (byte)0xf3, (byte)0x1e, (byte)0x80, (byte)0x87, (byte)0x7d
        };
        byte[] ret = aes.aesEcbDecrypt(aes_128bit_16byte, text);
        assertEquals("jetbrainintellijpasswordoverflow", new String(ret, StandardCharsets.UTF_8));
    }
}
