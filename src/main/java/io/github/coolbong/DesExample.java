package io.github.coolbong;


import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.paddings.ISO7816d4Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

import java.nio.charset.StandardCharsets;

public class DesExample {


    public byte[] desEcbEncryptEx01(byte[] text) throws InvalidCipherTextException {
        // TDES 2 key
        byte[] key = {
                (byte)0x40, (byte)0x41, (byte)0x42, (byte)0x43, (byte)0x44, (byte)0x45, (byte)0x46, (byte)0x47,
                (byte)0x48, (byte)0x49, (byte)0x4a, (byte)0x4b, (byte)0x4c, (byte)0x4d, (byte)0x4e, (byte)0x4f
        };

        BlockCipher engine = new DESedeEngine();
        BufferedBlockCipher cipher = new BufferedBlockCipher(engine);
        cipher.init(true, new KeyParameter(key));

        byte[] outBuff = new byte[text.length];
        int ret = cipher.processBytes(text, 0, text.length, outBuff, 0);
        cipher.doFinal(outBuff, ret);

        return outBuff;
    }


    public byte[] desEcbDecryptEx01(byte[] encrypted) throws InvalidCipherTextException {
        // TDES 2 key
        byte[] key = {
                (byte)0x40, (byte)0x41, (byte)0x42, (byte)0x43, (byte)0x44, (byte)0x45, (byte)0x46, (byte)0x47,
                (byte)0x48, (byte)0x49, (byte)0x4a, (byte)0x4b, (byte)0x4c, (byte)0x4d, (byte)0x4e, (byte)0x4f
        };

        BlockCipher engine = new DESedeEngine();
        BufferedBlockCipher cipher = new BufferedBlockCipher(engine);
        cipher.init(false, new KeyParameter(key));

        byte[] outBuff = new byte[encrypted.length];
        int ret = cipher.processBytes(encrypted, 0, encrypted.length, outBuff, 0);
        cipher.doFinal(outBuff, ret);

        return outBuff;
    }




    public byte[] desEcbEx02() throws InvalidCipherTextException {
        // TDES 2 key
        byte[] key = {
                (byte)0x40, (byte)0x41, (byte)0x42, (byte)0x43, (byte)0x44, (byte)0x45, (byte)0x46, (byte)0x47,
                (byte)0x48, (byte)0x49, (byte)0x4a, (byte)0x4b, (byte)0x4c, (byte)0x4d, (byte)0x4e, (byte)0x4f
        };
        // plaintext 16 byte
        byte[] text = "jetbrainintellij".getBytes(StandardCharsets.UTF_8);


        BlockCipher engine = new DESedeEngine();
        BufferedBlockCipher cipher = new BufferedBlockCipher(engine);
        cipher.init(true, new KeyParameter(key));

        byte[] outBuff = new byte[text.length];
        int ret = cipher.processBytes(text, 0, text.length, outBuff, 0);
        cipher.doFinal(outBuff, ret);

        return outBuff;
    }

    public byte[] desEcbEx03() throws InvalidCipherTextException {
        // TDES 2 key
        byte[] key = {
                (byte)0x40, (byte)0x41, (byte)0x42, (byte)0x43, (byte)0x44, (byte)0x45, (byte)0x46, (byte)0x47,
                (byte)0x48, (byte)0x49, (byte)0x4a, (byte)0x4b, (byte)0x4c, (byte)0x4d, (byte)0x4e, (byte)0x4f
        };
        // plaintext 10 byte
        byte[] text = "helloworld".getBytes(StandardCharsets.UTF_8);


        BlockCipher engine = new DESedeEngine();
        BufferedBlockCipher cipher = new BufferedBlockCipher(engine);
        //BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(engine, new ISO7816d4Padding());
        cipher.init(true, new KeyParameter(key));

        byte[] outBuff = new byte[text.length];
        System.out.println(cipher.getBlockSize());
        int ret = cipher.processBytes(text, 0, text.length, outBuff, 0);
        cipher.doFinal(outBuff, ret);

        return outBuff;
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
        DesExample ex = new DesExample();
        byte[] ret;

        byte[] text = "intellij".getBytes(StandardCharsets.UTF_8);
        ret = ex.desEcbEncryptEx01(text);
        print(ret);

        ret = ex.desEcbDecryptEx01(ret);
        System.out.println(new String(ret, StandardCharsets.UTF_8));

        ret = ex.desEcbEx02();
        print(ret);
        ret = ex.desEcbEx03();
        print(ret);

    }


}
