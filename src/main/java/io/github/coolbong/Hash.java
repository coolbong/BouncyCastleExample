package io.github.coolbong;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD5Digest;

public class Hash {


    public byte[] md5(byte[] text) {
        // create MD5 digest
        Digest digest = new MD5Digest();

        // get block size for output buffer
        int blockSize = digest.getDigestSize();
        byte[] buf = new byte[blockSize];

        digest.update(text, 0, text.length);
        digest.doFinal(buf, 0);
        return buf;
    }


}
