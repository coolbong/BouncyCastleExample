package io.github.coolbong;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.macs.*;
import org.bouncycastle.crypto.paddings.ISO7816d4Padding;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public class Mac {

    public byte[] hmacMd5(byte[] key, byte[] text) {
        HMac mac = new HMac(new MD5Digest());
        mac.init(new KeyParameter(key));
        int macSize = mac.getMacSize();
        byte[] output = new byte[macSize];
        mac.update(text, 0, text.length);
        mac.doFinal(output, 0);
        return output;
    }

    public byte[] hmacSha1(byte[] key, byte[] text) {
        HMac mac = new HMac(new SHA1Digest());
        mac.init(new KeyParameter(key));
        int macSize = mac.getMacSize();
        byte[] output = new byte[macSize];
        mac.update(text, 0, text.length);
        mac.doFinal(output, 0);
        return output;
    }


    public byte[] hmacSha256(byte[] key, byte[] text) {
        HMac mac = new HMac(new SHA256Digest());
        mac.init(new KeyParameter(key));
        int macSize = mac.getMacSize();
        byte[] output = new byte[macSize];
        mac.update(text, 0, text.length);
        mac.doFinal(output, 0);
        return output;
    }

    public byte[] aesCmac128(byte[] key, byte[] text) {
        //Create CMAC / AES / 128 bit
        CMac mac = new CMac(new AESEngine(), 128);
        mac.init(new KeyParameter(key));

        byte[] output = new byte[mac.getMacSize()];
        mac.update(text, 0, text.length);
        mac.doFinal(output, 0);
        return output;
    }

    public byte[] aesCmac128(byte[] key, byte[] text, byte[] iv) {
        //Create CMAC With IV / AES / 128 bit
        CMac mac = new CMacWithIV(new AESEngine(), 128);
        // create Key Parameter with IV
        mac.init(new ParametersWithIV(new KeyParameter(key), iv));
        byte[] output = new byte[mac.getMacSize()];
        mac.update(text, 0, text.length);
        mac.doFinal(output, 0);
        return output;
    }

    public byte[] aesMac(byte[] key, byte[] text, byte[] iv) {
        CBCBlockCipherMac mac = new CBCBlockCipherMac(new AESEngine(), 128, null);

        if (iv == null) {
            mac.init(new KeyParameter(key));
        } else {
            mac.init(new ParametersWithIV(new KeyParameter(key), iv));
        }

        byte[] output = new byte[mac.getMacSize()];
        mac.update(text, 0, text.length);
        mac.doFinal(output, 0);

        return output;
    }

    public byte[] desMac(byte[] key, byte[] text, byte[] iv) {
        CBCBlockCipherMac mac = new CBCBlockCipherMac(new DESedeEngine(), 64, null);

        if (iv == null) {
            mac.init(new KeyParameter(key));
        } else {
            mac.init(new ParametersWithIV(new KeyParameter(key), iv));
        }

        byte[] output = new byte[mac.getMacSize()];
        mac.update(text, 0, text.length);
        mac.doFinal(output, 0);

        return output;
    }




    public byte[] desMacMethod1Alg3(byte[] key, byte[] text, byte[] iv) {
        ISO9797Alg3Mac mac = new ISO9797Alg3Mac(new DESEngine(), 64, null);
        if (iv == null) {
            mac.init(new KeyParameter(key));
        } else {
            mac.init(new ParametersWithIV(new KeyParameter(key), iv));
        }
        byte[] output = new byte[mac.getMacSize()];
        mac.update(text, 0, text.length);
        mac.doFinal(output, 0);
        return output;
    }

    public byte[] desMacMethod2Alg3(byte[] key, byte[] text, byte[] iv) {
        ISO9797Alg3Mac mac = new ISO9797Alg3Mac(new DESEngine(), 64, new ISO7816d4Padding());
        if (iv == null) {
            mac.init(new KeyParameter(key));
        } else {
            mac.init(new ParametersWithIV(new KeyParameter(key), iv));
        }
        byte[] output = new byte[mac.getMacSize()];
        mac.update(text, 0, text.length);
        mac.doFinal(output, 0);
        return output;
    }

}
