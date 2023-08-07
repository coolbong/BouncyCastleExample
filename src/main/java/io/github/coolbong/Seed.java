package io.github.coolbong;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SEEDEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.nio.charset.StandardCharsets;

public class Seed {

    static final byte[] key = "ABCDEFGHIJKLMNOP".getBytes(StandardCharsets.UTF_8);


    public byte[] seedEcbEncrypt(byte[] key, byte[] text) throws InvalidCipherTextException {
        //create Seed Cipher
        BlockCipher engine = new SEEDEngine();
        BufferedBlockCipher cipher = new BufferedBlockCipher(engine);

        //cipher encryption init with key
        cipher.init(true, new KeyParameter(key));


        byte[] outBuff = new byte[cipher.getOutputSize(text.length)];
        int offset = cipher.processBytes(text, 0, text.length, outBuff, 0);
        cipher.doFinal(outBuff, offset);

        return outBuff;
    }

    public byte[] seedEcbDecrypt(byte[] key, byte[] text) throws InvalidCipherTextException {
        //create Seed Cipher
        BlockCipher engine = new SEEDEngine();
        BufferedBlockCipher cipher = new BufferedBlockCipher(engine);

        //cipher decryption init with key
        cipher.init(false, new KeyParameter(key));

        byte[] outBuff = new byte[cipher.getOutputSize(text.length)];
        int offset = cipher.processBytes(text, 0, text.length, outBuff, 0);
        cipher.doFinal(outBuff, offset);

        return outBuff;
    }

    public byte[] seedEcbPadEncrypt(byte[] key, byte[] text) throws InvalidCipherTextException {
        //create Seed Cipher
        BlockCipher engine = new SEEDEngine();
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(engine);

        // cipher encryption init with key
        cipher.init(true, new KeyParameter(key));

        byte[] outBuff = new byte[cipher.getOutputSize(text.length)];
        int offset = cipher.processBytes(text, 0, text.length, outBuff, 0);
        cipher.doFinal(outBuff, offset);

        return outBuff;
    }

    public byte[] seedEcbPadDecrypt(byte[] key, byte[] text) throws InvalidCipherTextException {
        // create Seed Cipher
        BlockCipher engine = new SEEDEngine();
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(engine);

        // cipher decryption init with key
        cipher.init(false, new KeyParameter(key));

        byte[] outBuff = new byte[cipher.getOutputSize(text.length)];
        int offset = cipher.processBytes(text, 0, text.length, outBuff, 0);
        cipher.doFinal(outBuff, offset);

        return outBuff;
    }


    public byte[] seedCbcEncrypt(byte[] key, byte[] text) throws InvalidCipherTextException {
        return seedCbcEncrypt(key, text, null);
    }

    public byte[] seedCbcDecrypt(byte[] key, byte[] text) throws InvalidCipherTextException {
        return seedCbcDecrypt(key, text, null);
    }

    public byte[] seedCbcEncrypt(byte[] key, byte[] text, byte[] iv) throws InvalidCipherTextException {
        if (iv == null) {
            iv = new byte[16];
        }

        //create Seed Cipher
        BlockCipher engine = new SEEDEngine();
        BufferedBlockCipher cipher = new BufferedBlockCipher(new CBCBlockCipher(engine));

        // cipher encryption init with key
        cipher.init(true, new ParametersWithIV(new KeyParameter(key), iv));

        byte[] outBuff = new byte[cipher.getOutputSize(text.length)];
        int offset = cipher.processBytes(text, 0, text.length, outBuff, 0);
        cipher.doFinal(outBuff, offset);

        return outBuff;
    }

    public byte[] seedCbcDecrypt(byte[] key, byte[] text, byte[] iv) throws InvalidCipherTextException {
        if (iv == null) {
            iv = new byte[16];
        }

        //create Seed Cipher
        BlockCipher engine = new SEEDEngine();
        BufferedBlockCipher cipher = new BufferedBlockCipher(new CBCBlockCipher(engine));

        //cipher decryption init with key
        cipher.init(false, new ParametersWithIV(new KeyParameter(key), iv));

        byte[] outBuff = new byte[cipher.getOutputSize(text.length)];
        int offset = cipher.processBytes(text, 0, text.length, outBuff, 0);
        cipher.doFinal(outBuff, offset);

        return outBuff;
    }


    public byte[] seedCbcPadEncrypt(byte[] key, byte[] text, byte[] iv) throws InvalidCipherTextException {
        if (iv == null) {
            iv = new byte[16];
        }

        // create Seed Cipher
        BlockCipher engine = new SEEDEngine();
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(engine));

        // cipher encryption init with key
        cipher.init(true, new ParametersWithIV(new KeyParameter(key), iv));

        byte[] outBuf = new byte[cipher.getOutputSize(text.length)];
        int offset = cipher.processBytes(text, 0, text.length, outBuf, 0);
        cipher.doFinal(outBuf, offset);

        return outBuf;
    }

    public byte[] seedCbcPadDecrypt(byte[] key, byte[] text, byte[] iv) throws InvalidCipherTextException {
        if (iv == null) {
            iv = new byte[16];
        }

        //create Seed Cipher
        BlockCipher engine = new SEEDEngine();
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(engine));

        // cipher decryption init with key
        cipher.init(false, new ParametersWithIV(new KeyParameter(key), iv));

        byte[] outBuf = new byte[cipher.getOutputSize(text.length)];
        int offset = cipher.processBytes(text, 0, text.length, outBuf, 0);
        cipher.doFinal(outBuf, offset);

        return outBuf;
    }


}
