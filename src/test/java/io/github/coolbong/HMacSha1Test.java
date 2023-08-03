package io.github.coolbong;

import org.junit.Test;

import static io.github.coolbong.Util.toBytes;
import static io.github.coolbong.Util.toHex;
import static org.junit.Assert.assertEquals;

public class HMacSha1Test {

    @Test
    public void hmac_sha1_rfc_2202_test_001() {
        byte[] key = toBytes("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B");
        byte[] msg = toBytes("4869205468657265");

        Mac mac = new Mac();
        byte[] ret = mac.hmacSha1(key, msg);
        assertEquals("B617318655057264E28BC0B6FB378C8EF146BE00", toHex(ret));
    }

    @Test
    public void hmac_sha1_rfc_2202_test_002() {
        byte[] key = toBytes("4A656665");
        byte[] msg = toBytes("7768617420646F2079612077616E7420666F72206E6F7468696E673F");

        Mac mac = new Mac();
        byte[] ret = mac.hmacSha1(key, msg);
        assertEquals("EFFCDF6AE5EB2FA2D27416D5F184DF9C259A7C79", toHex(ret));
    }


    @Test
    public void hmac_sha1_rfc_2202_test_003() {
        byte[] key = toBytes("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        byte[] msg = toBytes("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD");

        Mac mac = new Mac();
        byte[] ret = mac.hmacSha1(key, msg);
        assertEquals("125D7342B9AC11CD91A39AF48AA17B4F63F175D3", toHex(ret));
    }

    @Test
    public void hmac_sha1_rfc_2202_test_004() {
        byte[] key = toBytes("0102030405060708090A0B0C0D0E0F10111213141516171819");
        byte[] msg = toBytes("CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD");

        Mac mac = new Mac();
        byte[] ret = mac.hmacSha1(key, msg);
        assertEquals("4C9007F4026250C6BC8414F9BF50C86C2D7235DA", toHex(ret));
    }

    @Test
    public void hmac_sha1_rfc_2202_test_005() {
        byte[] key = toBytes("0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C");
        byte[] msg = toBytes("546573742057697468205472756E636174696F6E");

        Mac mac = new Mac();
        byte[] ret = mac.hmacSha1(key, msg);
        assertEquals("4C1A03424B55E07FE7F27BE1D58BB9324A9A5A04", toHex(ret));
    }

    @Test
    public void hmac_sha1_rfc_2202_test_006() {
        byte[] key = toBytes("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        byte[] msg = toBytes("54657374205573696E67204C6172676572205468616E20426C6F636B2D53697A65204B6579202D2048617368204B6579204669727374");

        Mac mac = new Mac();
        byte[] ret = mac.hmacSha1(key, msg);
        assertEquals("AA4AE5E15272D00E95705637CE8A3B55ED402112", toHex(ret));
    }

    @Test
    public void hmac_sha1_rfc_2202_test_007() {
        byte[] key = toBytes("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        byte[] msg = toBytes("54657374205573696E67204C6172676572205468616E20426C6F636B2D53697A65204B657920616E64204C6172676572205468616E204F6E6520426C6F636B2D53697A652044617461");

        Mac mac = new Mac();
        byte[] ret = mac.hmacSha1(key, msg);
        assertEquals("E8E99D0F45237D786D6BBAA7965C7808BBFF1A91", toHex(ret));
    }

}
