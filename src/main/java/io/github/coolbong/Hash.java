package io.github.coolbong;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;

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


    public byte[] sha1(byte[] text) {
        // create sha1 digest
        Digest digest = new SHA1Digest();

        //get block size for output buffer
        int blockSize = digest.getDigestSize();
        byte[] buf = new byte[blockSize];

        digest.update(text, 0, text.length);
        digest.doFinal(buf, 0);
        return buf;
    }


    public byte[] sha256(byte[] text) {
        // create sha256 digest
        Digest digest = new SHA256Digest();

        //get block size for output buffer
        int blockSize = digest.getDigestSize();
        byte[] buf = new byte[blockSize];

        digest.update(text, 0, text.length);
        digest.doFinal(buf, 0);
        return buf;
    }

    public byte[] sha512(byte[] text) {
        // create sha512 digest
        Digest digest = new SHA512Digest();

        //get block size for output buffer
        int blockSize = digest.getDigestSize();
        byte[] buf = new byte[blockSize];

        digest.update(text, 0, text.length);
        digest.doFinal(buf, 0);
        return buf;
    }



}
