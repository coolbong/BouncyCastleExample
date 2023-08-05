package io.github.coolbong;

import org.junit.Test;

import java.io.File;
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

    @Test
    public void hash_sha1_test_001() {
        byte[] text = "Hello world".getBytes(StandardCharsets.UTF_8);
        Hash hash = new Hash();
        byte[] ret = hash.sha1(text);
        assertEquals("7B502C3A1F48C8609AE212CDFB639DEE39673F5E", toHex(ret));
    }

    @Test
    public void hash_sha256_test_001() {
        byte[] text = "Hello world".getBytes(StandardCharsets.UTF_8);
        Hash hash = new Hash();
        byte[] ret = hash.sha256(text);
        assertEquals("64EC88CA00B268E5BA1A35678A1B5316D212F4F366B2477232534A8AECA37F3C", toHex(ret));
    }

    @Test
    public void hash_sha256_test_002() {
        File file = Util.getResourceFile("hash/node-v18.17.0-headers.tar.xz");

        Hash hash = new Hash();
        byte[] output = hash.sha256(file);
        assertEquals("1A7A3BBB7299F69E16A8EE2B327DD1C4811A9376BCAFE41F8310467A9A9E3307", toHex(output));
    }

    @Test
    public void hash_sha512_test_001() {
        byte[] text = "Hello world".getBytes(StandardCharsets.UTF_8);
        Hash hash = new Hash();
        byte[] ret = hash.sha512(text);
        assertEquals("B7F783BAED8297F0DB917462184FF4F08E69C2D5E5F79A942600F9725F58CE1F" +
                "29C18139BF80B06C0FFF2BDD34738452ECF40C488C22A7E3D80CDF6F9C1C0D47", toHex(ret));
    }




}
