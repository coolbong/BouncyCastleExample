package io.github.coolbong;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.prng.DigestRandomGenerator;
import org.bouncycastle.crypto.prng.RandomGenerator;

public class Random {

    public byte[] rand(int length) {
        // create random generator (sha1 digest)
        RandomGenerator generator = new DigestRandomGenerator(new SHA1Digest());
        // add seed
        generator.addSeedMaterial(System.nanoTime());
        byte[] buf = new byte[length];
        // generate
        generator.nextBytes(buf);
        return buf;
    }
}
