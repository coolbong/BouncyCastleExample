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
        byte[] ret = aes.aesEcbEncrypt(aes_256bit_32byte, text);
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
        byte[] ret = aes.aesEcbEncrypt(aes_192bit_24byte, text);
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

    @Test
    public void aes_cbc_256_encrypt() throws InvalidCipherTextException {
        Aes aes = new Aes();
        byte[] ret = aes.aesCbcEncrypt(aes_256bit_32byte, text, null);
        //System.out.println(to_bytes_variable(ret));
        assertEquals("6F8E0CF5903A79673E8863E47D7E2008E1DA98BA9E7DF32C2F50618EADEAA53D", toHex(ret));
    }

    @Test
    public void aes_cbc_256_decrypt() throws InvalidCipherTextException {
        Aes aes = new Aes();
        byte[] text = {
                (byte)0x6f, (byte)0x8e, (byte)0x0c, (byte)0xf5, (byte)0x90, (byte)0x3a, (byte)0x79, (byte)0x67,
                (byte)0x3e, (byte)0x88, (byte)0x63, (byte)0xe4, (byte)0x7d, (byte)0x7e, (byte)0x20, (byte)0x08,
                (byte)0xe1, (byte)0xda, (byte)0x98, (byte)0xba, (byte)0x9e, (byte)0x7d, (byte)0xf3, (byte)0x2c,
                (byte)0x2f, (byte)0x50, (byte)0x61, (byte)0x8e, (byte)0xad, (byte)0xea, (byte)0xa5, (byte)0x3d
        };
        byte[] ret = aes.aesCbcDecrypt(aes_256bit_32byte, text, null);
        assertEquals("jetbrainintellijpasswordoverflow", new String(ret, StandardCharsets.UTF_8));
    }

    @Test
    public void aes_cbc_192_encrypt() throws InvalidCipherTextException {
        Aes aes = new Aes();
        byte[] ret = aes.aesCbcEncrypt(aes_192bit_24byte, text, null);
        assertEquals("F31848F53CC2DBCD77AE068BA224EACF574EAE507587FBF49C8B6DDC4C275A6E", toHex(ret));
    }

    @Test
    public void aes_cbc_192_decrypt() throws InvalidCipherTextException {
        Aes aes = new Aes();
        byte[] text = {
                (byte)0xf3, (byte)0x18, (byte)0x48, (byte)0xf5, (byte)0x3c, (byte)0xc2, (byte)0xdb, (byte)0xcd,
                (byte)0x77, (byte)0xae, (byte)0x06, (byte)0x8b, (byte)0xa2, (byte)0x24, (byte)0xea, (byte)0xcf,
                (byte)0x57, (byte)0x4e, (byte)0xae, (byte)0x50, (byte)0x75, (byte)0x87, (byte)0xfb, (byte)0xf4,
                (byte)0x9c, (byte)0x8b, (byte)0x6d, (byte)0xdc, (byte)0x4c, (byte)0x27, (byte)0x5a, (byte)0x6e
        };
        byte[] ret = aes.aesCbcDecrypt(aes_192bit_24byte, text, null);
        assertEquals("jetbrainintellijpasswordoverflow", new String(ret, StandardCharsets.UTF_8));
    }

    @Test
    public void aes_cbc_128_encrypt() throws InvalidCipherTextException {
        Aes aes = new Aes();
        byte[] ret = aes.aesCbcEncrypt(aes_128bit_16byte, text, null);
        //System.out.println(to_bytes_variable(ret));
        assertEquals("3D17A921520E975F22BD902EAB28E8BCE84C105D480680B4DCED7D6318F6CBEE", toHex(ret));
    }

    @Test
    public void aes_cbc_128_decrypt() throws InvalidCipherTextException {
        Aes aes = new Aes();
        byte[] text = {
                (byte)0x3d, (byte)0x17, (byte)0xa9, (byte)0x21, (byte)0x52, (byte)0x0e, (byte)0x97, (byte)0x5f,
                (byte)0x22, (byte)0xbd, (byte)0x90, (byte)0x2e, (byte)0xab, (byte)0x28, (byte)0xe8, (byte)0xbc,
                (byte)0xe8, (byte)0x4c, (byte)0x10, (byte)0x5d, (byte)0x48, (byte)0x06, (byte)0x80, (byte)0xb4,
                (byte)0xdc, (byte)0xed, (byte)0x7d, (byte)0x63, (byte)0x18, (byte)0xf6, (byte)0xcb, (byte)0xee
        };
        byte[] ret = aes.aesCbcDecrypt(aes_128bit_16byte, text, null);
        assertEquals("jetbrainintellijpasswordoverflow", new String(ret, StandardCharsets.UTF_8));
    }


    @Test
    public void aes_ctr_256_encrypt() throws InvalidCipherTextException {
        Aes aes = new Aes();
        byte[] ret = aes.aesCtrEncrypt(aes_256bit_32byte, text, null);
        assertEquals("EAC01D5F2D62F9F27614B7E3FAA897EF2C555D9AD1834063E5D93994F8A84EE0", toHex(ret));
    }

    @Test
    public void aes_ctr_256_decrypt() throws InvalidCipherTextException {
        Aes aes = new Aes();
        byte[] text = {
                (byte)0xea, (byte)0xc0, (byte)0x1d, (byte)0x5f, (byte)0x2d, (byte)0x62, (byte)0xf9, (byte)0xf2,
                (byte)0x76, (byte)0x14, (byte)0xb7, (byte)0xe3, (byte)0xfa, (byte)0xa8, (byte)0x97, (byte)0xef,
                (byte)0x2c, (byte)0x55, (byte)0x5d, (byte)0x9a, (byte)0xd1, (byte)0x83, (byte)0x40, (byte)0x63,
                (byte)0xe5, (byte)0xd9, (byte)0x39, (byte)0x94, (byte)0xf8, (byte)0xa8, (byte)0x4e, (byte)0xe0
        };
        byte[] ret = aes.aesCtrDecrypt(aes_256bit_32byte, text, null);
        assertEquals("jetbrainintellijpasswordoverflow", new String(ret, StandardCharsets.UTF_8));
    }

    @Test
    public void aes_ctr_192_encrypt() throws InvalidCipherTextException {
        Aes aes = new Aes();
        byte[] ret = aes.aesCtrEncrypt(aes_192bit_24byte, text, null);
        assertEquals("2390A065D44876702A53AA176F4E5080F1C1F8F924B79F73CC3B9428F09BAC32", toHex(ret));
    }

    @Test
    public void aes_ctr_192_decrypt() throws InvalidCipherTextException {
        Aes aes = new Aes();
        byte[] text = {
                (byte)0x23, (byte)0x90, (byte)0xa0, (byte)0x65, (byte)0xd4, (byte)0x48, (byte)0x76, (byte)0x70,
                (byte)0x2a, (byte)0x53, (byte)0xaa, (byte)0x17, (byte)0x6f, (byte)0x4e, (byte)0x50, (byte)0x80,
                (byte)0xf1, (byte)0xc1, (byte)0xf8, (byte)0xf9, (byte)0x24, (byte)0xb7, (byte)0x9f, (byte)0x73,
                (byte)0xcc, (byte)0x3b, (byte)0x94, (byte)0x28, (byte)0xf0, (byte)0x9b, (byte)0xac, (byte)0x32
        };
        byte[] ret = aes.aesCtrDecrypt(aes_192bit_24byte, text, null);
        assertEquals("jetbrainintellijpasswordoverflow", new String(ret, StandardCharsets.UTF_8));
    }

    @Test
    public void aes_ctr_128_encrypt() throws InvalidCipherTextException {
        Aes aes = new Aes();
        byte[] ret = aes.aesCtrEncrypt(aes_128bit_16byte, text, null);
        System.out.println(to_bytes_variable(ret));
        assertEquals("EF10A58AE1F010B3C10B6A8B4494F417324F6FE6230B8012FC490D43BF67C94A", toHex(ret));
    }

    @Test
    public void aes_ctr_128_decrypt() throws InvalidCipherTextException {
        Aes aes = new Aes();
        byte[] text = {
                (byte)0xef, (byte)0x10, (byte)0xa5, (byte)0x8a, (byte)0xe1, (byte)0xf0, (byte)0x10, (byte)0xb3,
                (byte)0xc1, (byte)0x0b, (byte)0x6a, (byte)0x8b, (byte)0x44, (byte)0x94, (byte)0xf4, (byte)0x17,
                (byte)0x32, (byte)0x4f, (byte)0x6f, (byte)0xe6, (byte)0x23, (byte)0x0b, (byte)0x80, (byte)0x12,
                (byte)0xfc, (byte)0x49, (byte)0x0d, (byte)0x43, (byte)0xbf, (byte)0x67, (byte)0xc9, (byte)0x4a
        };
        byte[] ret = aes.aesCtrDecrypt(aes_128bit_16byte, text, null);
        assertEquals("jetbrainintellijpasswordoverflow", new String(ret, StandardCharsets.UTF_8));
    }
}
