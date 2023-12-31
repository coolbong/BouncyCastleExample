package io.github.coolbong;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.Test;

import static io.github.coolbong.Util.*;
import static junit.framework.TestCase.assertEquals;

public class SeedTest {


    @Test
    public void seed_ecb_encrypt_test_001() throws InvalidCipherTextException {
        byte[] txt = {
                (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07,
                (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f
        };
        byte[] key = {
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
        };

        Seed seed = new Seed();
        byte[] ret = seed.seedEcbEncrypt(key, txt);

        assertEquals("5EBAC6E0054E166819AFF1CC6D346CDB", toHex(ret));
    }

    @Test
    public void seed_ecb_decrypt_test_001() throws InvalidCipherTextException {
        byte[] key = {
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
        };

        byte[] anw = {
                (byte)0x5e, (byte)0xba, (byte)0xc6, (byte)0xe0, (byte)0x05, (byte)0x4e, (byte)0x16, (byte)0x68,
                (byte)0x19, (byte)0xaf, (byte)0xf1, (byte)0xcc, (byte)0x6d, (byte)0x34, (byte)0x6c, (byte)0xdb
        };

        Seed seed = new Seed();
        byte[] ret = seed.seedEcbDecrypt(key, anw);

        assertEquals("000102030405060708090A0B0C0D0E0F", toHex(ret));
    }


    @Test
    public void seed_cbc_encrypt_test_001() throws InvalidCipherTextException {
        byte[] txt = { (byte)0x12, (byte)0x34, (byte)0x00, (byte)0x00, (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x80, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00 };
        byte[] anw = { (byte)0x6c, (byte)0x71, (byte)0xe6, (byte)0x0d, (byte)0xef, (byte)0x88, (byte)0x4c, (byte)0x34, (byte)0xc8, (byte)0x10, (byte)0x90, (byte)0x42, (byte)0x97, (byte)0xb4, (byte)0x4f, (byte)0x3c };
        byte[] key = { (byte)0x40, (byte)0x41, (byte)0x42, (byte)0x43, (byte)0x44, (byte)0x45, (byte)0x46, (byte)0x47, (byte)0x48, (byte)0x49, (byte)0x4a, (byte)0x4b, (byte)0x4c, (byte)0x4d, (byte)0x4e, (byte)0x4f };

        Seed seed = new Seed();
        byte[] ret = seed.seedCbcEncrypt(key, txt);

        assertEquals("6C71E60DEF884C34C810904297B44F3C", toHex(ret));
    }


    @Test
    public void seed_cbc_decrypt_test_001() throws InvalidCipherTextException {
        byte[] txt = { (byte)0x12, (byte)0x34, (byte)0x00, (byte)0x00, (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x80, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00 };
        byte[] anw = { (byte)0x6c, (byte)0x71, (byte)0xe6, (byte)0x0d, (byte)0xef, (byte)0x88, (byte)0x4c, (byte)0x34, (byte)0xc8, (byte)0x10, (byte)0x90, (byte)0x42, (byte)0x97, (byte)0xb4, (byte)0x4f, (byte)0x3c };
        byte[] key = { (byte)0x40, (byte)0x41, (byte)0x42, (byte)0x43, (byte)0x44, (byte)0x45, (byte)0x46, (byte)0x47, (byte)0x48, (byte)0x49, (byte)0x4a, (byte)0x4b, (byte)0x4c, (byte)0x4d, (byte)0x4e, (byte)0x4f };

        Seed seed = new Seed();
        byte[] ret = seed.seedCbcDecrypt(key, anw);

        assertEquals("12340000010000800000000000000000", toHex(ret));
    }

    @Test
    public void seed_cbc_encrypt_test_002() throws InvalidCipherTextException {
        byte[] txt = toBytes("000102030405060708090A0B0C0D0E0F");
        byte[] anw = toBytes("75DDA4B065FF86427D448C5403D35A07");
        byte[] key = toBytes("88E34F8F081779F1E9F394370AD40589");
        byte[] iv = toBytes("268D66A735A81A816FBAD9FA36162501");

        Seed seed = new Seed();
        byte[] ret = seed.seedCbcEncrypt(key, txt, iv);

        assertEquals("75DDA4B065FF86427D448C5403D35A07", toHex(ret));
    }

    @Test
    public void seed_cvc_decrypt_test_002() throws InvalidCipherTextException {
        byte[] txt = toBytes("000102030405060708090A0B0C0D0E0F");
        byte[] anw = toBytes("75DDA4B065FF86427D448C5403D35A07");
        byte[] key = toBytes("88E34F8F081779F1E9F394370AD40589");
        byte[] iv = toBytes("268D66A735A81A816FBAD9FA36162501");

        Seed seed = new Seed();
        byte[] ret = seed.seedCbcDecrypt(key, anw, iv);

        assertEquals("000102030405060708090A0B0C0D0E0F", toHex(ret));
    }

}
