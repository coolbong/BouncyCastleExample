package io.github.coolbong;


import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static io.github.coolbong.Util.toHex;
import static io.github.coolbong.Util.print;


public class Des {


    public byte[] desEcbEncrypt(byte[] key, byte[] text) throws InvalidCipherTextException {
        // create TDES cipher
        BlockCipher engine = new DESedeEngine();
        BufferedBlockCipher cipher = new BufferedBlockCipher(engine);
        // set key
        cipher.init(true, new KeyParameter(key));

        byte[] outBuff = new byte[cipher.getOutputSize(text.length)];
        int offset = cipher.processBytes(text, 0, text.length, outBuff, 0);
        cipher.doFinal(outBuff, offset);

        return outBuff;
    }


    public byte[] desEcbDecrypt(byte[] key, byte[] text) throws InvalidCipherTextException {
        // create TDES cipher
        BlockCipher engine = new DESedeEngine();
        BufferedBlockCipher cipher = new BufferedBlockCipher(engine);
        // set key
        cipher.init(false, new KeyParameter(key));

        byte[] outBuff = new byte[cipher.getOutputSize(text.length)];
        int offset = cipher.processBytes(text, 0, text.length, outBuff, 0);
        cipher.doFinal(outBuff, offset);

        return outBuff;
    }

    public byte[] desEcbPadEncrypt(byte[] key, byte[] text) throws InvalidCipherTextException {
        // create TDES cipher
        BlockCipher engine = new DESedeEngine();
        // Padding cipher (adjust input data length to des block size)
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(engine);
        // set key
        cipher.init(true, new KeyParameter(key));

        // get output buffer size
        int outputSize = cipher.getOutputSize(text.length);
        // create output buffer
        byte[] outBuff = new byte[outputSize];
        int offset = cipher.processBytes(text, 0, text.length, outBuff, 0);
        cipher.doFinal(outBuff, offset);

        return outBuff;
    }

    public byte[] desEcbPadDecrypt(byte[] key, byte[] text) throws InvalidCipherTextException {
        // create TDES cipher
        BlockCipher engine = new DESedeEngine();
        // Padding cipher (adjust input data length to des block size)
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(engine);
        // set key
        cipher.init(false, new KeyParameter(key));

        // get output buffer size
        int outputSize = cipher.getOutputSize(text.length);
        // create output buffer
        byte[] outBuff = new byte[outputSize];
        int offset = cipher.processBytes(text, 0, text.length, outBuff, 0);
        int ret = cipher.doFinal(outBuff, offset);

        return Arrays.copyOf(outBuff, offset+ret);
    }


    public byte[] desCbcEncrypt(byte[] key, byte[] text, byte[] iv) throws InvalidCipherTextException {
        // create default initialize vector
        if (iv == null) {
            iv = new byte[8];
        }
        // create TDES cipher
        BlockCipher engine = new DESedeEngine();
        BufferedBlockCipher cipher = new BufferedBlockCipher(new CBCBlockCipher(engine));
        // set key with iv
        cipher.init(true, new ParametersWithIV(new KeyParameter(key), iv));

        byte[] outBuff = new byte[cipher.getOutputSize(text.length)];
        int offset = cipher.processBytes(text, 0, text.length, outBuff, 0);
        cipher.doFinal(outBuff, offset);

        return outBuff;
    }

    public byte[] desCbcDecrypt(byte[] key, byte[] text, byte[] iv) throws InvalidCipherTextException {
        // create default initialize vector
        if (iv == null) {
            iv = new byte[8];
        }
        // create TDES cipher
        BlockCipher engine = new DESedeEngine();
        BufferedBlockCipher cipher = new BufferedBlockCipher(new CBCBlockCipher(engine));
        // set key with iv
        cipher.init(false, new ParametersWithIV(new KeyParameter(key), iv));

        byte[] outBuff = new byte[cipher.getOutputSize(text.length)];
        int offset = cipher.processBytes(text, 0, text.length, outBuff, 0);
        cipher.doFinal(outBuff, offset);

        return outBuff;
    }

    public byte[] desCbcPadEncrypt(byte[] key, byte[] text, byte[] iv) throws InvalidCipherTextException {
        // create default initialize vector
        if (iv == null) {
            iv = new byte[8];
        }
        // create TDES cipher
        BlockCipher engine = new DESedeEngine();
        // Padding cipher (adjust input data length to des block size)
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(engine));
        // set key
        cipher.init(true, new ParametersWithIV(new KeyParameter(key), iv));

        // get output buffer size
        int outputSize = cipher.getOutputSize(text.length);
        // create output buffer
        byte[] outBuff = new byte[outputSize];
        int offset = cipher.processBytes(text, 0, text.length, outBuff, 0);
        cipher.doFinal(outBuff, offset);

        return outBuff;
    }

    public byte[] desCbcPadDecrypt(byte[] key, byte[] text, byte[] iv) throws InvalidCipherTextException {
        // create default initialize vector
        if (iv == null) {
            iv = new byte[8];
        }
        // create TDES cipher
        BlockCipher engine = new DESedeEngine();
        // Padding cipher (adjust input data length to des block size)
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(engine));
        // set key
        cipher.init(false, new ParametersWithIV(new KeyParameter(key), iv));

        // get output buffer size
        int outputSize = cipher.getOutputSize(text.length);
        // create output buffer
        byte[] outBuff = new byte[outputSize];
        int offset = cipher.processBytes(text, 0, text.length, outBuff, 0);
        int ret = cipher.doFinal(outBuff, offset);

        return Arrays.copyOf(outBuff, offset+ret);
    }

    public static void main(String[] args) throws Exception {

        // TDES 2 key
        byte[] key = {
                (byte)0x40, (byte)0x41, (byte)0x42, (byte)0x43, (byte)0x44, (byte)0x45, (byte)0x46, (byte)0x47,
                (byte)0x48, (byte)0x49, (byte)0x4a, (byte)0x4b, (byte)0x4c, (byte)0x4d, (byte)0x4e, (byte)0x4f
        };

        // des ecb example
        Des ex = new Des();
        byte[] ret;
        byte[] text;

//        text = "intellij".getBytes(StandardCharsets.UTF_8);
//        ret = ex.desEcbEncrypt(key, text);
//        print(ret);
//
//        ret = ex.desEcbDecrypt(key, ret);
//        System.out.println(new String(ret, StandardCharsets.UTF_8));
//
//        // des cbc example
//        text = "jetbrainintellij".getBytes(StandardCharsets.UTF_8);
//        ret = ex.desCbcEncrypt(key, text, null);
//        print(ret);
//
//        ret = ex.desCbcDecrypt(key, ret, null);
//        System.out.println(new String(ret, StandardCharsets.UTF_8));


        text = "hello world".getBytes(StandardCharsets.UTF_8);
        ret = ex.desEcbPadEncrypt(key, text);
        print(ret);

        ret = ex.desEcbPadDecrypt(key, ret);
        System.out.println(new String(ret, StandardCharsets.UTF_8));


        text = "hello world".getBytes(StandardCharsets.UTF_8);
        ret = ex.desCbcPadEncrypt(key, text, null);
        System.out.println(toHex(ret));
        print(ret);

        ret = ex.desCbcPadDecrypt(key, ret, null);
        System.out.println(new String(ret, StandardCharsets.UTF_8));

    }


}
