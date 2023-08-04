package io.github.coolbong;

import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class Rsa {



    public RSAPrivateKey readPrivateKey(File file) throws IOException{
        FileReader reader = new FileReader(file);
        return readPrivateKey(reader);
    }

    public RSAPrivateKey readPrivateKey(Reader reader) throws IOException {
        PemReader pemReader = new PemReader(reader);
        PemObject pemObj = pemReader.readPemObject();

        return RSAPrivateKey.getInstance(pemObj.getContent());
    }


    public RSAPublicKey readPublicKey(File file) {
        try {
            PemReader reader = new PemReader(new FileReader(file));
            PemObject pemObj = reader.readPemObject();

            KeyFactory kf = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pemObj.getContent());
            java.security.interfaces.RSAPublicKey rsaPublicKey = (java.security.interfaces.RSAPublicKey) kf.generatePublic(keySpec);
            BigInteger m = rsaPublicKey.getModulus();
            BigInteger e = rsaPublicKey.getPublicExponent();

            return new RSAPublicKey(m, e);
            //return RSAPublicKey.getInstance(pemObj.getContent());
        } catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException ignored) {
        }
        return null;
    }

}
