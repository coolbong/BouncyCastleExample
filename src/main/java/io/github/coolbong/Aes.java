package io.github.coolbong;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.KeyParameter;

import java.nio.charset.StandardCharsets;

import static io.github.coolbong.Util.print;

public class Aes {

    static byte[] aes_128bit_16byte = "ABCDEFGHIJKLMNOP".getBytes(StandardCharsets.UTF_8);
    static byte[] aes_192bit_24byte = "ABCDEFGHIJKLMNOPQRSTUVWX".getBytes(StandardCharsets.UTF_8);
    static byte[] aes_256bit_32byte = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef".getBytes(StandardCharsets.UTF_8);


    public byte[] aesEcbEncrypt(byte[] key, byte[] text) throws InvalidCipherTextException {
        // create AES cipher
        BlockCipher engine = new AESEngine();
        BufferedBlockCipher cipher = new BufferedBlockCipher(engine);
        // set key
        cipher.init(true, new KeyParameter(key));

        byte[] outBuff = new byte[text.length];
        int offset = cipher.processBytes(text, 0, text.length, outBuff, 0);
        cipher.doFinal(outBuff, offset);

        return outBuff;
    }

    public byte[] aesEcbDectypt(byte[] key, byte[] text) throws InvalidCipherTextException {
        // create AES cipher
        BlockCipher engine = new AESEngine();
        BufferedBlockCipher cipher = new BufferedBlockCipher(engine);
        // set key
        cipher.init(false, new KeyParameter(key));

        byte[] outBuff = new byte[text.length];
        int offset = cipher.processBytes(text, 0, text.length, outBuff, 0);
        cipher.doFinal(outBuff, offset);

        return outBuff;
    }



    void aesEcbExample() throws InvalidCipherTextException {
        byte[] text = "jetbrainintellij".getBytes(StandardCharsets.UTF_8);
        byte[] ret;


        ret = aesEcbEncrypt(aes_128bit_16byte, text);
        print(ret);
        ret = aesEcbDectypt(aes_128bit_16byte, ret);
        System.out.println(new String(ret, StandardCharsets.UTF_8));

        ret = aesEcbEncrypt(aes_192bit_24byte, text);
        print(ret);
        ret = aesEcbDectypt(aes_192bit_24byte, ret);
        System.out.println(new String(ret, StandardCharsets.UTF_8));

        ret = aesEcbEncrypt(aes_256bit_32byte, text);
        print(ret);
        ret = aesEcbDectypt(aes_256bit_32byte, ret);
        System.out.println(new String(ret, StandardCharsets.UTF_8));

    }


    public static void main(String args[]) throws Exception {
        Aes aes = new Aes();
        aes.aesEcbExample();


    }
}
