package io.github.coolbong;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static io.github.coolbong.Util.print;
import static io.github.coolbong.Util.toHex;

public class Aes {

    static final byte[] aes_128bit_16byte = "ABCDEFGHIJKLMNOP".getBytes(StandardCharsets.UTF_8);
    static final byte[] aes_192bit_24byte = "ABCDEFGHIJKLMNOPQRSTUVWX".getBytes(StandardCharsets.UTF_8);
    static final byte[] aes_256bit_32byte = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef".getBytes(StandardCharsets.UTF_8);


    public byte[] aesEcbEncrypt(byte[] key, byte[] text) throws InvalidCipherTextException {
        // create AES cipher
        BlockCipher engine = new AESEngine();
        BufferedBlockCipher cipher = new BufferedBlockCipher(engine);
        // set key
        cipher.init(true, new KeyParameter(key));

        byte[] outBuff = new byte[cipher.getOutputSize(text.length)];
        int offset = cipher.processBytes(text, 0, text.length, outBuff, 0);
        cipher.doFinal(outBuff, offset);

        return outBuff;
    }

    public byte[] aesEcbDecrypt(byte[] key, byte[] text) throws InvalidCipherTextException {
        // create AES cipher
        BlockCipher engine = new AESEngine();
        BufferedBlockCipher cipher = new BufferedBlockCipher(engine);
        // set key
        cipher.init(false, new KeyParameter(key));

        byte[] outBuff = new byte[cipher.getOutputSize(text.length)];
        int offset = cipher.processBytes(text, 0, text.length, outBuff, 0);
        cipher.doFinal(outBuff, offset);

        return outBuff;
    }

    public byte[] aesEcbPadEncrypt(byte[] key, byte[] text) throws InvalidCipherTextException {
        // create AES cipher
        BlockCipher engine = new AESEngine();
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(engine);
        // set key
        cipher.init(true, new KeyParameter(key));

        int outputSize = cipher.getOutputSize(text.length);
        byte[] outBuff = new byte[outputSize];
        int offset = cipher.processBytes(text, 0, text.length, outBuff, 0);
        cipher.doFinal(outBuff, offset);

        return outBuff;
    }

    public byte[] aesEcbPadDecrypt(byte[] key, byte[] text) throws InvalidCipherTextException {
        // create AES cipher
        BlockCipher engine = new AESEngine();
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(engine);
        // set key
        cipher.init(false, new KeyParameter(key));

        int outputSize = cipher.getOutputSize(text.length);
        byte[] outBuff = new byte[outputSize];
        int offset = cipher.processBytes(text, 0, text.length, outBuff, 0);
        int ret = cipher.doFinal(outBuff, offset);

        return Arrays.copyOf(outBuff, offset+ret);
    }


    public byte[] aesCbcEncrypt(byte[] key, byte[] text, byte[] iv) throws InvalidCipherTextException {
        // create default initialize vector
        if (iv == null) {
            iv = new byte[16];
        }
        // create AES cipher
        BlockCipher engine = new AESEngine();
        BufferedBlockCipher cipher = new BufferedBlockCipher(new CBCBlockCipher(engine));
        // set key with iv
        cipher.init(true, new ParametersWithIV(new KeyParameter(key), iv));

        byte[] outBuff = new byte[cipher.getOutputSize(text.length)];
        int offset = cipher.processBytes(text, 0, text.length, outBuff, 0);
        cipher.doFinal(outBuff, offset);

        return outBuff;
    }

    public byte[] aesCbcDecrypt(byte[] key, byte[] text, byte[] iv) throws InvalidCipherTextException {
        // create default initialize vector
        if (iv == null) {
            iv = new byte[16];
        }
        // create AES cipher
        BlockCipher engine = new AESEngine();
        BufferedBlockCipher cipher = new BufferedBlockCipher(new CBCBlockCipher(engine));
        // set key with iv
        cipher.init(false, new ParametersWithIV(new KeyParameter(key), iv));

        byte[] outBuff = new byte[cipher.getOutputSize(text.length)];
        int offset = cipher.processBytes(text, 0, text.length, outBuff, 0);
        cipher.doFinal(outBuff, offset);

        return outBuff;
    }

    public byte[] aesCbcPadEncrypt(byte[] key, byte[] text, byte[] iv) throws InvalidCipherTextException {
        if (iv == null) {
            iv = new byte[16];
        }
        // create AES cipher
        BlockCipher engine = new AESEngine();
        // Padding cipher (adjust input data length to des block size)
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(engine));
        // set key
        cipher.init(true, new ParametersWithIV(new KeyParameter(key), iv));

        int outputSize = cipher.getOutputSize(text.length);
        byte[] outBuff = new byte[outputSize];
        int offset = cipher.processBytes(text, 0, text.length, outBuff, 0);
        cipher.doFinal(outBuff, offset);

        return outBuff;
    }

    public byte[] aesCbcPadDecrypt(byte[] key, byte[] text, byte[] iv) throws InvalidCipherTextException {
        if (iv == null) {
            iv = new byte[16];
        }
        // create AES cipher
        BlockCipher engine = new AESEngine();
        // Padding cipher (adjust input data length to des block size)
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(engine));
        // set key
        cipher.init(false, new ParametersWithIV(new KeyParameter(key), iv));

        int outputSize = cipher.getOutputSize(text.length);
        byte[] outBuff = new byte[outputSize];
        int offset = cipher.processBytes(text, 0, text.length, outBuff, 0);
        int ret = cipher.doFinal(outBuff, offset);

        return Arrays.copyOf(outBuff, offset+ret);
    }

    public byte[] aesCtrEncrypt(byte[] key, byte[] text, byte[] iv) throws InvalidCipherTextException {
        // create default initialize vector
        if (iv == null) {
            iv = new byte[16];
        }
        // create AES cipher
        BlockCipher engine = new AESEngine();
        BufferedBlockCipher cipher = new BufferedBlockCipher(new SICBlockCipher(engine));
        // set key with iv
        cipher.init(true, new ParametersWithIV(new KeyParameter(key), iv));

        byte[] outBuff = new byte[text.length];
        int offset = cipher.processBytes(text, 0, text.length, outBuff, 0);
        cipher.doFinal(outBuff, offset);

        return outBuff;
    }

    public byte[] aesCtrDecrypt(byte[] key, byte[] text, byte[] iv) throws InvalidCipherTextException {
        // create default initialize vector
        if (iv == null) {
            iv = new byte[16];
        }
        // create AES cipher
        BlockCipher engine = new AESEngine();
        BufferedBlockCipher cipher = new BufferedBlockCipher(new SICBlockCipher(engine));
        // set key with iv
        cipher.init(false, new ParametersWithIV(new KeyParameter(key), iv));

        byte[] outBuff = new byte[cipher.getOutputSize(text.length)];
        int offset = cipher.processBytes(text, 0, text.length, outBuff, 0);
        cipher.doFinal(outBuff, offset);

        return outBuff;
    }

    public byte[] aesCtrPadEncrypt(byte[] key, byte[] text, byte[] iv) throws InvalidCipherTextException {
        if (iv == null) {
            iv = new byte[16];
        }
        // create AES cipher
        BlockCipher engine = new AESEngine();
        // Padding cipher (adjust input data length to des block size)
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new SICBlockCipher(engine));
        // set key
        cipher.init(true, new ParametersWithIV(new KeyParameter(key), iv));

        int outputSize = cipher.getOutputSize(text.length);
        byte[] outBuff = new byte[outputSize];
        int offset = cipher.processBytes(text, 0, text.length, outBuff, 0);
        cipher.doFinal(outBuff, offset);

        return outBuff;
    }

    public byte[] aesCtrPadDecrypt(byte[] key, byte[] text, byte[] iv) throws InvalidCipherTextException {
        if (iv == null) {
            iv = new byte[16];
        }
        // create AES cipher
        BlockCipher engine = new AESEngine();
        // Padding cipher (adjust input data length to des block size)
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new SICBlockCipher(engine));
        // set key
        cipher.init(false, new ParametersWithIV(new KeyParameter(key), iv));

        int outputSize = cipher.getOutputSize(text.length);
        byte[] outBuff = new byte[outputSize];
        int offset = cipher.processBytes(text, 0, text.length, outBuff, 0);
        int ret = cipher.doFinal(outBuff, offset);

        return Arrays.copyOf(outBuff, offset+ret);
    }


    void aesEcbExample() throws InvalidCipherTextException {
        byte[] text = "jetbrainintellijpasswordoverflow".getBytes(StandardCharsets.UTF_8);
        byte[] ret;

        ret = aesEcbEncrypt(aes_128bit_16byte, text);
        print(ret);
        ret = aesEcbDecrypt(aes_128bit_16byte, ret);
        System.out.println(new String(ret, StandardCharsets.UTF_8));

        ret = aesEcbEncrypt(aes_192bit_24byte, text);
        print(ret);
        ret = aesEcbDecrypt(aes_192bit_24byte, ret);
        System.out.println(new String(ret, StandardCharsets.UTF_8));

        ret = aesEcbEncrypt(aes_256bit_32byte, text);
        print(ret);
        ret = aesEcbDecrypt(aes_256bit_32byte, ret);
        System.out.println(new String(ret, StandardCharsets.UTF_8));
    }

    void aesEcbPadExample() throws InvalidCipherTextException {
        byte[] text = "pass".getBytes(StandardCharsets.UTF_8);
        byte[] ret;

        ret = aesEcbPadEncrypt(aes_128bit_16byte, text);
        print(ret);
        ret = aesEcbPadDecrypt(aes_128bit_16byte, ret);
        System.out.println(new String(ret, StandardCharsets.UTF_8));

        ret = aesEcbPadEncrypt(aes_192bit_24byte, text);
        print(ret);
        ret = aesEcbPadDecrypt(aes_192bit_24byte, ret);
        System.out.println(new String(ret, StandardCharsets.UTF_8));

        ret = aesEcbPadEncrypt(aes_256bit_32byte, text);
        print(ret);
        ret = aesEcbPadDecrypt(aes_256bit_32byte, ret);
        System.out.println(new String(ret, StandardCharsets.UTF_8));
    }

    void aesCbcExample() throws InvalidCipherTextException {
        byte[] text = "jetbrainintellijpasswordoverflow".getBytes(StandardCharsets.UTF_8);
        byte[] ret;

        ret = aesCbcEncrypt(aes_128bit_16byte, text, null);
        print(ret);
        ret = aesCbcDecrypt(aes_128bit_16byte, ret, null);
        System.out.println(new String(ret, StandardCharsets.UTF_8));

        ret = aesCbcEncrypt(aes_192bit_24byte, text, null);
        print(ret);
        ret = aesCbcDecrypt(aes_192bit_24byte, ret, null);
        System.out.println(new String(ret, StandardCharsets.UTF_8));

        ret = aesCbcEncrypt(aes_256bit_32byte, text, null);
        print(ret);
        ret = aesCbcDecrypt(aes_256bit_32byte, ret, null);
        System.out.println(new String(ret, StandardCharsets.UTF_8));
    }

    void aesCbcPadExample() throws InvalidCipherTextException {
        byte[] text = "pass".getBytes(StandardCharsets.UTF_8);
        byte[] ret;

        ret = aesCbcPadEncrypt(aes_128bit_16byte, text, null);
        print(ret);
        ret = aesCbcPadDecrypt(aes_128bit_16byte, ret, null);
        System.out.println(new String(ret, StandardCharsets.UTF_8));

        ret = aesCbcPadEncrypt(aes_192bit_24byte, text, null);
        print(ret);
        ret = aesCbcPadDecrypt(aes_192bit_24byte, ret, null);
        System.out.println(new String(ret, StandardCharsets.UTF_8));

        ret = aesCbcPadEncrypt(aes_256bit_32byte, text, null);
        print(ret);
        ret = aesCbcPadDecrypt(aes_256bit_32byte, ret, null);
        System.out.println(new String(ret, StandardCharsets.UTF_8));
    }

    void aesCtrExample() throws InvalidCipherTextException {
        byte[] text = "jetbrainintellijpasswordoverflow".getBytes(StandardCharsets.UTF_8);
        //System.out.println(toHex(text));
        byte[] iv = new byte[16];
        iv[15] = 0x01;
        byte[] ret;

        ret = aesCtrEncrypt(aes_128bit_16byte, text, null);
        //print(ret);
        System.out.println(toHex(ret));
        ret = aesCtrDecrypt(aes_128bit_16byte, ret, null);
        System.out.println(new String(ret, StandardCharsets.UTF_8));

        ret = aesCtrEncrypt(aes_192bit_24byte, text, null);
        //print(ret);
        System.out.println(toHex(ret));
        ret = aesCtrDecrypt(aes_192bit_24byte, ret, null);
        System.out.println(new String(ret, StandardCharsets.UTF_8));

        ret = aesCtrEncrypt(aes_256bit_32byte, text, null);
        //print(ret);
        System.out.println(toHex(ret));
        ret = aesCtrDecrypt(aes_256bit_32byte, ret, null);
        System.out.println(new String(ret, StandardCharsets.UTF_8));



        ret = aesCtrEncrypt(aes_128bit_16byte, text, iv);
        print(ret);
        System.out.println(toHex(ret));
        ret = aesCtrDecrypt(aes_128bit_16byte, ret, iv);
        System.out.println(new String(ret, StandardCharsets.UTF_8));

        ret = aesCtrEncrypt(aes_192bit_24byte, text, iv);
        print(ret);
        System.out.println(toHex(ret));
        ret = aesCtrDecrypt(aes_192bit_24byte, ret, iv);
        System.out.println(new String(ret, StandardCharsets.UTF_8));

        ret = aesCtrEncrypt(aes_256bit_32byte, text, iv);
        print(ret);
        System.out.println(toHex(ret));
        ret = aesCtrDecrypt(aes_256bit_32byte, ret, iv);
        System.out.println(new String(ret, StandardCharsets.UTF_8));
    }

    void aesCtrPadExample() throws InvalidCipherTextException {
        byte[] text = "pass".getBytes(StandardCharsets.UTF_8);
        byte[] ret;

        ret = aesCtrPadEncrypt(aes_128bit_16byte, text, null);
        print(ret);
        ret = aesCtrPadDecrypt(aes_128bit_16byte, ret, null);
        System.out.println(new String(ret, StandardCharsets.UTF_8));

        ret = aesCtrPadEncrypt(aes_192bit_24byte, text, null);
        print(ret);
        ret = aesCtrPadDecrypt(aes_192bit_24byte, ret, null);
        System.out.println(new String(ret, StandardCharsets.UTF_8));

        ret = aesCtrPadEncrypt(aes_256bit_32byte, text, null);
        print(ret);
        ret = aesCtrPadDecrypt(aes_256bit_32byte, ret, null);
        System.out.println(new String(ret, StandardCharsets.UTF_8));
    }


    public static void main(String[] args) throws Exception {
        Aes aes = new Aes();
        //aes.aesEcbExample();
        //aes.aesCbcExample();
        aes.aesCtrExample();
        //aes.aesEcbPadExample();
        //aes.aesCbcPadExample();
        //aes.aesCtrPadExample();

    }
}
