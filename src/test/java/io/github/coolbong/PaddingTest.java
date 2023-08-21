package io.github.coolbong;

import org.junit.Assert;
import org.junit.Test;

import java.util.Arrays;

import static io.github.coolbong.Util.toHex;

public class PaddingTest {



    @Test
    public void test_padding_001() {
        byte[] answer = {(byte)0x5A, (byte)0x5A, (byte)0x5A, (byte)0x5A, (byte)0x5A, (byte)0x00, (byte)0x00, (byte)0x00 };
        byte[] data = new byte[5];
        Arrays.fill(data, (byte)0x5A);

        Padding padding = new Padding();
        byte[] ret = padding.zeroPadding(data, 8);

        Assert.assertArrayEquals(answer, ret);
    }


    @Test
    public void test_padding_002() {
        byte[] answer = {(byte)0x5A, (byte)0x5A, (byte)0x5A, (byte)0x5A, (byte)0x5A, (byte)0x03, (byte)0x03, (byte)0x03 };
        byte[] data = new byte[5];
        Arrays.fill(data, (byte)0x5A);

        Padding padding = new Padding();
        byte[] ret = padding.pkcs7Padding(data, 8);

        System.out.println(toHex(data));
        System.out.println(toHex(ret));
        Assert.assertArrayEquals(answer, ret);
    }

    @Test
    public void test_padding_003() {
        byte[] answer = {(byte)0x5A, (byte)0x5A, (byte)0x5A, (byte)0x5A, (byte)0x5A, (byte)0x80, (byte)0x00, (byte)0x00 };
        byte[] data = new byte[5];
        Arrays.fill(data, (byte)0x5A);

        Padding padding = new Padding();
        byte[] ret = padding.desPadding(data, 8);

        Assert.assertArrayEquals(answer, ret);
    }

    @Test
    public void test_padding_004() {
        byte[] answer = {(byte)0x5A, (byte)0x5A, (byte)0x5A, (byte)0x5A, (byte)0x5A, (byte)0x80, (byte)0x67, (byte)0x03 };
        byte[] data = new byte[5];
        Arrays.fill(data, (byte)0x5A);

        Padding padding = new Padding();
        byte[] ret = padding.is1026dPadding(data, 8);

        System.out.println(toHex(ret));
        //Assert.assertArrayEquals(answer, ret);
    }


    //
    @Test
    public void test_padding_005() {
        byte[] answer = {(byte)0x5A, (byte)0x5A, (byte)0x5A, (byte)0x5A, (byte)0x5A, (byte)0xff, (byte)0xff, (byte)0xff };
        byte[] data = new byte[5];
        Arrays.fill(data, (byte)0x5A);

        Padding padding = new Padding();
        byte[] ret = padding.tbcPadding(data, 8);

        //System.out.println(toHex(ret));
        Assert.assertArrayEquals(answer, ret);
    }


    @Test
    public void test_padding_006() {
        byte[] answer = {(byte)0x5A, (byte)0x5A, (byte)0x5A, (byte)0x5A, (byte)0x5A, (byte)0x00, (byte)0x00, (byte)0x03 };
        byte[] data = new byte[5];
        Arrays.fill(data, (byte)0x5A);

        Padding padding = new Padding();
        byte[] ret = padding.x923Padding(data, 8);

        Assert.assertArrayEquals(answer, ret);
    }


    @Test
    public void test_padding_106() {
        byte[] answer = {
                (byte)0x5A, (byte)0x5A, (byte)0x5A, (byte)0x5A, (byte)0x5A, (byte)0x5A, (byte)0x5A, (byte)0x5A,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x08
        };
        byte[] data = new byte[8];
        Arrays.fill(data, (byte)0x5A);

        Padding padding = new Padding();
        byte[] ret = padding.x923Padding(data, 8);

        //System.out.println(toHex(ret));
        Assert.assertArrayEquals(answer, ret);
    }
}
