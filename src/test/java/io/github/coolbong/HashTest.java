package io.github.coolbong;

import org.junit.Test;

import java.nio.charset.StandardCharsets;

import static io.github.coolbong.Util.toHex;
import static junit.framework.TestCase.assertEquals;

public class HashTest {


    @Test
    public void hash_md5_test_001() {
        byte[] text = "Hello world".getBytes(StandardCharsets.UTF_8);
        Hash hash = new Hash();
        byte[] ret = hash.md5(text);
        assertEquals("3E25960A79DBC69B674CD4EC67A72C62", toHex(ret));
    }
}
