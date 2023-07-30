package io.github.coolbong;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

import static io.github.coolbong.Util.toHex;
import static io.github.coolbong.Util.to_bytes_variable;
import static junit.framework.TestCase.assertEquals;

public class DesTest {

    byte[] des1Key = {
            (byte) 0x40, (byte) 0x41, (byte) 0x42, (byte) 0x43, (byte) 0x44, (byte) 0x45, (byte) 0x46, (byte) 0x47,
    };

    // TDES 2 key
    byte[] des2key = {
            (byte)0x40, (byte)0x41, (byte)0x42, (byte)0x43, (byte)0x44, (byte)0x45, (byte)0x46, (byte)0x47,
            (byte)0x48, (byte)0x49, (byte)0x4a, (byte)0x4b, (byte)0x4c, (byte)0x4d, (byte)0x4e, (byte)0x4f
    };

    @Test
    public void des_ecb_encrypt() throws InvalidCipherTextException {
        Des des = new Des();
        byte[] text = "intellij".getBytes(StandardCharsets.UTF_8);
        byte[] ret = des.desEcbEncrypt(des2key, text);
        //System.out.println(to_bytes_variable(ret));

        assertEquals("DFCF5DF219288DD5", toHex(ret));
    }

    @Test
    public void des_ecb_decrypt() throws InvalidCipherTextException {
        Des des = new Des();
        byte[] text = {(byte)0xdf, (byte)0xcf, (byte)0x5d, (byte)0xf2, (byte)0x19, (byte)0x28, (byte)0x8d, (byte)0xd5};

        byte[] ret = des.desEcbDecrypt(des2key, text);
        assertEquals("intellij", new String(ret, StandardCharsets.UTF_8));
    }


    @Test
    public void des_ecb_encrypt_with_padding() throws InvalidCipherTextException {
        Des des = new Des();
        byte[] text = "hello world".getBytes(StandardCharsets.UTF_8);
        byte[] ret = des.desEcbPaddEncrypt(des2key, text);

        assertEquals("3C05C505BE37C540CA105B9C2FAD62DC", toHex(ret));
    }

    @Test
    public void des_ecb_decrypt_with_padding() throws InvalidCipherTextException {
        Des des = new Des();
        byte[] text = {
                (byte)0x3c, (byte)0x05, (byte)0xc5, (byte)0x05,
                (byte)0xbe, (byte)0x37, (byte)0xc5, (byte)0x40,
                (byte)0xca, (byte)0x10, (byte)0x5b, (byte)0x9c,
                (byte)0x2f, (byte)0xad, (byte)0x62, (byte)0xdc
        };
        byte[] ret = des.desEcbPaddDecrypt(des2key, text);

        //System.out.println(to_bytes_variable(ret));
        //System.out.println(toHex(ret));
        assertEquals("hello world", new String(ret, StandardCharsets.UTF_8));
    }

    @Test
    public void des_cbc_encrypt() throws InvalidCipherTextException {
        Des des = new Des();

        byte[] text = "jetbrainintellij".getBytes(StandardCharsets.UTF_8);
        byte[] ret = des.desCbcEncrypt(des2key, text, null);

        //System.out.println(to_bytes_variable(ret));

        assertEquals("A97648A3ABA5BE36421DCB237A94119C", toHex(ret));
    }

    @Test
    public void des_cbc_descrypt() throws InvalidCipherTextException {
        Des des = new Des();
        byte[] text = {
                (byte)0xa9, (byte)0x76, (byte)0x48, (byte)0xa3,
                (byte)0xab, (byte)0xa5, (byte)0xbe, (byte)0x36,
                (byte)0x42, (byte)0x1d, (byte)0xcb, (byte)0x23,
                (byte)0x7a, (byte)0x94, (byte)0x11, (byte)0x9c
        };

        byte[] ret = des.desCbcDecrypt(des2key, text, null);

        assertEquals("jetbrainintellij", new String(ret, StandardCharsets.UTF_8));
    }

    @Test
    public void des_cbc_encrypt_with_padding() throws InvalidCipherTextException {
        Des des = new Des();
        byte[] text = "hello world".getBytes(StandardCharsets.UTF_8);
        byte[] ret = des.desCbcPaddEncrypt(des2key, text, null);

        //System.out.println(to_bytes_variable(ret));

        assertEquals("3C05C505BE37C540CF44C48887FE9561", toHex(ret));
    }

    @Test
    public void des_cbc_decrypt_with_padding() throws InvalidCipherTextException {
        Des des = new Des();
        byte[] text = {
                (byte)0x3c, (byte)0x05, (byte)0xc5, (byte)0x05,
                (byte)0xbe, (byte)0x37, (byte)0xc5, (byte)0x40,
                (byte)0xcf, (byte)0x44, (byte)0xc4, (byte)0x88,
                (byte)0x87, (byte)0xfe, (byte)0x95, (byte)0x61
        };
        byte[] ret = des.desCbcPaddDecrypt(des2key, text, null);

        assertEquals("hello world", new String(ret, StandardCharsets.UTF_8));
    }


}
