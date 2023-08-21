package io.github.coolbong;

import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class Rsa {



    // read rsa key  from file
    public RSAPrivateKey readPemPrivateKey(File file) throws IOException{
        FileReader reader = new FileReader(file);
        return readPemPrivateKey(reader);
    }

    public RSAPrivateKey readPemPrivateKey(Reader reader) throws IOException {
        PemReader pemReader = new PemReader(reader);
        PemObject pemObj = pemReader.readPemObject();

        return RSAPrivateKey.getInstance(pemObj.getContent());
    }


    public RSAPublicKey readPemPublicKey(File file) throws IOException {
        return readPemPublicKey(new FileReader(file));
    }

    public RSAPublicKey readPemPublicKey(Reader reader) {
        try {
            PemReader pemReader = new PemReader(reader);
            PemObject pemObj = pemReader.readPemObject();

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


    // rsa key generation
    public static final BigInteger RSA_KEY_PUBLIC_EXPONENT = BigInteger.valueOf(0x10001);
    public static final int RSA_KEY_DEFAULT_CERTAINTY = 80;
    public AsymmetricCipherKeyPair generateRsaKey(int bit) throws NoSuchAlgorithmException {

        RSAKeyGenerationParameters pram = new RSAKeyGenerationParameters(
                RSA_KEY_PUBLIC_EXPONENT,
                new SecureRandom(),
                bit,
                RSA_KEY_DEFAULT_CERTAINTY
        );

        RSAKeyPairGenerator generator = new RSAKeyPairGenerator();
        generator.init(pram);
        AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();

        //System.out.println(keyPair);
        //System.out.println(keyPair.getPrivate());
        //System.out.println(keyPair.getPublic());

        //RSAKeyParameters privateKey = (RSAKeyParameters)keyPair.getPrivate();
        return keyPair;

    }


    public byte[] encrypt(byte[] m, byte[] e, byte[] txt) {
        RSAEngine engine = new RSAEngine();
        // RSA Key param, public key modulus, public key exponent
        RSAKeyParameters param = new RSAKeyParameters(false, new BigInteger(1, m), new BigInteger(1, e));
        // init for encryption
        engine.init(true, param);
        return engine.processBlock(txt, 0, txt.length);
    }

    public byte[] encrypt(BigInteger m, BigInteger e, byte[] txt) {
        RSAEngine engine = new RSAEngine();
        // RSA Key param, public key modulus, public key exponent
        RSAKeyParameters param = new RSAKeyParameters(false, m, e);
        // init for encryption
        engine.init(true, param);
        return engine.processBlock(txt, 0, txt.length);
    }

    public byte[] decrypt(byte[] m, byte[] e, byte[] txt) {
        RSAEngine engine = new RSAEngine();
        // RSA Key param, private key modulus, private key exponent
        RSAKeyParameters param = new RSAKeyParameters(true, new BigInteger(1, m), new BigInteger(1, e));
        // init for decryption
        engine.init(false, param);
        return engine.processBlock(txt, 0, txt.length);
    }

    public byte[] decrypt(BigInteger m, BigInteger e, byte[] txt) {

        RSAEngine engine = new RSAEngine();
        // RSA Key param, private key modulus,private key exponent
        RSAKeyParameters param = new RSAKeyParameters(true, m, e);
        // init for decryption
        engine.init(false, param);
        return engine.processBlock(txt, 0, txt.length);
    }


    public byte[] decrypt(byte[] p, byte[] q, byte[] dp1, byte[] dq1, byte[] qInv, byte[] txt) {
        return decrypt(
                new BigInteger(1, p),
                new BigInteger(1, q),
                new BigInteger(1, dp1),
                new BigInteger(1, dq1),
                new BigInteger(1, qInv),
                txt);
    }

    public byte[] decrypt(BigInteger p, BigInteger q, BigInteger dp1, BigInteger dq1, BigInteger qInv, byte[] txt) {

        RSAEngine engine = new RSAEngine();
        BigInteger m = p.multiply(q);
        // create RSA private CTR Key param
        RSAPrivateCrtKeyParameters param = new RSAPrivateCrtKeyParameters(
                m,      // modulus
                null,   // public exponent
                null,   // private exponent
                p,      // p
                q,      // q
                dp1,    // dP
                dq1,    // dQ
                qInv    // qInv
        );
        // init for decryption
        engine.init(false, param);
        return engine.processBlock(txt, 0, txt.length);
    }

}
