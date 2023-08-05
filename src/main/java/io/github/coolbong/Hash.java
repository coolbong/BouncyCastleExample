package io.github.coolbong;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

public class Hash {


    public byte[] md5(byte[] text) {
        // create MD5 digest
        Digest digest = new MD5Digest();

        // get block size for output buffer
        int hashSize = digest.getDigestSize();
        byte[] buf = new byte[hashSize];

        digest.update(text, 0, text.length);
        digest.doFinal(buf, 0);
        return buf;
    }


    public byte[] sha1(byte[] text) {
        // create sha1 digest
        Digest digest = new SHA1Digest();

        //get block size for output buffer
        int hashSize = digest.getDigestSize();
        byte[] buf = new byte[hashSize];

        digest.update(text, 0, text.length);
        digest.doFinal(buf, 0);
        return buf;
    }


    public byte[] sha256(byte[] text) {
        // create sha256 digest
        Digest digest = new SHA256Digest();

        //get block size for output buffer
        int hashSize = digest.getDigestSize();
        byte[] buf = new byte[hashSize];

        digest.update(text, 0, text.length);
        digest.doFinal(buf, 0);
        return buf;
    }

    public byte[] sha512(byte[] text) {
        // create sha512 digest
        Digest digest = new SHA512Digest();

        //get block size for output buffer
        int hashSize = digest.getDigestSize();
        byte[] buf = new byte[hashSize];

        digest.update(text, 0, text.length);
        digest.doFinal(buf, 0);
        return buf;
    }


    public byte[] sha256(File file) {
        Digest digest = new SHA256Digest();

        int hashSize = digest.getDigestSize();
        byte[] outBuff = new byte[hashSize];


        byte[] buf = new byte[4*1024]; // 4KB
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(file);
            int len;
            while ((len = fis.read(buf)) > 0) {
                digest.update(buf, 0, len);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        } finally {
            if (fis != null) {
                try { fis.close(); } catch (Exception ign) {}
            }
        }

        digest.doFinal(outBuff, 0);
        return outBuff;
    }



}
