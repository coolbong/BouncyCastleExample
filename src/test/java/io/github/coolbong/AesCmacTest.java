package io.github.coolbong;

import org.junit.Test;

import static io.github.coolbong.Util.toBytes;
import static io.github.coolbong.Util.toHex;
import static org.junit.Assert.assertEquals;

public class AesCmacTest {

    @Test
    public void aes_cmac_128_test_001() {
        byte[] key = toBytes("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B");
        byte[] msg = toBytes("4869205468657265");

        Mac mac = new Mac();
        byte[] ret = mac.aesCmac128(key, msg);
        assertEquals("A962DD30ACD5BFED671C4BB64E8FBE42", toHex(ret));
    }

    @Test
    public void aes_cmac_128_test_002() {
        byte[] key = toBytes("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B");
        byte[] msg = toBytes("4869205468657265");
        byte[] iv = toBytes("00000000000000000000000000000000");

        Mac mac = new Mac();
        byte[] ret = mac.aesCmac128(key, msg, iv);
        assertEquals("A962DD30ACD5BFED671C4BB64E8FBE42", toHex(ret));
    }

}
