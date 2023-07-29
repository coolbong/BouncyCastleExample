package io.github.coolbong;


import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.ISO7816d4Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.nio.charset.StandardCharsets;

import static io.github.coolbong.Util.toHex;

public class Des {


    public byte[] desEcbEncrypt(byte[] key, byte[] text) throws InvalidCipherTextException {
        // create TDES cipher
        BlockCipher engine = new DESedeEngine();
        BufferedBlockCipher cipher = new BufferedBlockCipher(engine);
        // set key
        cipher.init(true, new KeyParameter(key));

        byte[] outBuff = new byte[text.length];
        int offset = cipher.processBytes(text, 0, text.length, outBuff, 0);
        cipher.doFinal(outBuff, offset);

        return outBuff;
    }


    public byte[] desEcbDecrypt(byte[] key, byte[] encrypted) throws InvalidCipherTextException {
        // create TDES cipher
        BlockCipher engine = new DESedeEngine();
        BufferedBlockCipher cipher = new BufferedBlockCipher(engine);
        // set key
        cipher.init(false, new KeyParameter(key));

        byte[] outBuff = new byte[encrypted.length];
        int offset = cipher.processBytes(encrypted, 0, encrypted.length, outBuff, 0);
        cipher.doFinal(outBuff, offset);

        return outBuff;
    }

    public byte[] desCbcEncrypt(byte[] key, byte[] text, byte[] iv) throws InvalidCipherTextException {
        // TDES 2 key
        if (iv == null) {
            iv = new byte[8];
        }
        BlockCipher engine = new DESedeEngine();
        BufferedBlockCipher cipher = new BufferedBlockCipher(new CBCBlockCipher(engine));
        cipher.init(true, new ParametersWithIV(new KeyParameter(key), iv));

        byte[] outBuff = new byte[text.length];
        int offset = cipher.processBytes(text, 0, text.length, outBuff, 0);
        cipher.doFinal(outBuff, offset);

        return outBuff;
    }

    public byte[] desCbcDecrypt(byte[] key, byte[] text, byte[] iv) throws InvalidCipherTextException {
        // TDES 2 key
        if (iv == null) {
            iv = new byte[8];
        }
        BlockCipher engine = new DESedeEngine();
        BufferedBlockCipher cipher = new BufferedBlockCipher(new CBCBlockCipher(engine));
        cipher.init(false, new ParametersWithIV(new KeyParameter(key), iv));

        byte[] outBuff = new byte[text.length];
        int offset = cipher.processBytes(text, 0, text.length, outBuff, 0);
        cipher.doFinal(outBuff, offset);

        return outBuff;
    }

    public void desEcbExample() throws InvalidCipherTextException {

        // user password encryption example
        String password = "LoremIpsum";
        byte[] input = password.getBytes(StandardCharsets.UTF_8);
        // 16 bytes des key
        byte[] key = "passwordwordpass".getBytes(StandardCharsets.UTF_8);

        // TDES engine
        BlockCipher engine = new DESedeEngine();
        // Padding cipher (adjust input data length to des block size)
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(engine);
        // set key
        cipher.init(true, new KeyParameter(key));

        // get output buffer size
        int outputSize = cipher.getOutputSize(input.length);
        // create output buffer
        byte[] outBuff = new byte[outputSize];
        int offset = cipher.processBytes(input, 0, input.length, outBuff, 0);
        cipher.doFinal(outBuff, offset);

        System.out.println(toHex(outBuff));
    }

    public static void print(byte[] arr) {
        StringBuilder sb = new StringBuilder();
        for (byte b : arr) {
            sb.append(String.format("%02X:", b));
        }
        sb.deleteCharAt(sb.length() - 1);
        System.out.println(sb);
    }





    public static void main(String[] args) throws Exception {

        // TDES 2 key
        byte[] key = {
                (byte)0x40, (byte)0x41, (byte)0x42, (byte)0x43, (byte)0x44, (byte)0x45, (byte)0x46, (byte)0x47,
                (byte)0x48, (byte)0x49, (byte)0x4a, (byte)0x4b, (byte)0x4c, (byte)0x4d, (byte)0x4e, (byte)0x4f
        };

        Des ex = new Des();
        byte[] ret;

        byte[] text = "intellij".getBytes(StandardCharsets.UTF_8);
        ret = ex.desEcbEncrypt(key, text);
        print(ret);

        ret = ex.desEcbDecrypt(key, ret);
        System.out.println(new String(ret, StandardCharsets.UTF_8));

        //ex.desEcbExample();

    }


}
