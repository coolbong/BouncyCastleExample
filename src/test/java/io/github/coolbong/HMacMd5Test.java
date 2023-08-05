package io.github.coolbong;

import org.junit.Test;

import static io.github.coolbong.Util.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

public class HMacMd5Test {

    @Test
    public void hmac_md5_rfc_2202_test_001() {
        byte[] key = {
                (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b,
                (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b
        };
        byte[] msg = {
                (byte)0x48, (byte)0x69, (byte)0x20, (byte)0x54, (byte)0x68, (byte)0x65, (byte)0x72, (byte)0x65
        };

        Mac mac = new Mac();
        byte[] ret = mac.hmacMd5(key, msg);

        assertEquals("9294727A3638BB1C13F48EF8158BFC9D", toHex(ret));
    }

    @Test
    public void hmac_md5_rfc_2202_test_002() {
        byte[] key = toBytes("4A656665");
        byte[] msg = toBytes("7768617420646F2079612077616E7420666F72206E6F7468696E673F");

        Mac mac = new Mac();
        byte[] ret = mac.hmacMd5(key, msg);
        assertEquals("750C783E6AB0B503EAA86E310A5DB738", toHex(ret));
    }


    @Test
    public void hmac_md5_rfc_2202_test_003() {
        byte[] key = toBytes("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        byte[] msg = toBytes("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD");

        Mac mac = new Mac();
        byte[] ret = mac.hmacMd5(key, msg);
        assertEquals("56BE34521D144C88DBB8C733F0E8B3F6", toHex(ret));
    }

    @Test
    public void hmac_md5_rfc_2202_test_004() {
        byte[] key = toBytes("0102030405060708090A0B0C0D0E0F10111213141516171819");
        byte[] msg = toBytes("CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD");

        Mac mac = new Mac();
        byte[] ret = mac.hmacMd5(key, msg);
        assertEquals("697EAF0ACA3A3AEA3A75164746FFAA79", toHex(ret));
    }

    @Test
    public void hmac_md5_rfc_2202_test_005() {
        byte[] key = toBytes("0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C");
        byte[] msg = toBytes("546573742057697468205472756E636174696F6E");

        Mac mac = new Mac();
        byte[] ret = mac.hmacMd5(key, msg);
        assertEquals("56461EF2342EDC00F9BAB995690EFD4C", toHex(ret));
    }

    @Test
    public void hmac_md5_rfc_2202_test_006() {
        byte[] key = toBytes("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        byte[] msg = toBytes("54657374205573696E67204C6172676572205468616E20426C6F636B2D53697A65204B6579202D2048617368204B6579204669727374");

        Mac mac = new Mac();
        byte[] ret = mac.hmacMd5(key, msg);
        assertEquals("6B1AB7FE4BD7BF8F0B62E6CE61B9D0CD", toHex(ret));
    }

    @Test
    public void hmac_md5_rfc_2202_test_007() {
        byte[] key = toBytes("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        byte[] msg = toBytes("54657374205573696E67204C6172676572205468616E20426C6F636B2D53697A65204B657920616E64204C6172676572205468616E204F6E6520426C6F636B2D53697A652044617461");

        Mac mac = new Mac();
        byte[] ret = mac.hmacMd5(key, msg);
        assertEquals("6F630FAD67CDA0EE1FB1F562DB3AA53E", toHex(ret));
    }

}
