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

}
