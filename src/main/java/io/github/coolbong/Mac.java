package io.github.coolbong;

import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.macs.CMacWithIV;
import org.bouncycastle.crypto.macs.HMac;
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
        CMac mac = new CMac(new AESEngine(), 128);
        mac.init(new KeyParameter(key));
        byte[] output = new byte[mac.getMacSize()];
        mac.update(text, 0, text.length);
        mac.doFinal(output, 0);
        return output;
    }

    public byte[] aesCmac128(byte[] key, byte[] text, byte[] iv) {
        CMac mac = new CMacWithIV(new AESEngine(), 128);
        mac.init(new ParametersWithIV(new KeyParameter(key), iv));
        byte[] output = new byte[mac.getMacSize()];
        mac.update(text, 0, text.length);
        mac.doFinal(output, 0);
        return output;
    }

}
