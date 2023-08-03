package io.github.coolbong;

import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.junit.Test;

import java.io.File;
import java.math.BigInteger;
import java.net.URL;

import static io.github.coolbong.Util.toHex;
import static junit.framework.TestCase.assertEquals;

public class RsaTest {


    @Test
    public void rsa_test_001() {
        // pem parse online: https://8gwifi.org/PemParserFunctions.jsp

        String m_ans = "00:E0:63:FD:FA:2F:3B:A5:A7:6D:0A:82:34:AB:03:04:" +
                "C1:9F:E8:69:05:13:2F:11:22:1E:7A:8A:1F:88:E8:FF:" +
                "1D:89:2D:7B:1D:88:B3:0E:D4:2E:34:5D:1B:3C:09:34:" +
                "EC:56:44:E0:98:0B:20:52:23:03:AA:42:62:56:05:61:61";
        String e_ans = "01:00:01";
        String d_ans = "56:EA:44:51:29:04:78:98:CE:62:B8:A6:7F:EB:0E:67:95:71:E7:63:E0:D7:65:52:8A:ED:BA:1C:96:E2:71:16:1C:ED:74:C4:1C:8B:FE:E4:A1:33:67:A8:44:35:B7:B7:DA:F1:F4:FC:81:17:DA:34:D6:39:BA:6E:EE:FE:5A:35";

        String p_ans = "00:F7:59:8E:CD:29:2C:54:28:99:A5:BB:49:E2:06:D1:43:99:9B:4B:53:85:5F:35:28:06:5A:AF:4F:AB:CE:FF:73";
        String q_ans = "00:E8:3C:E3:40:8E:A4:12:3A:B6:20:F6:64:2F:A4:C8:AB:F7:AB:7D:61:E8:92:18:67:B5:4F:7C:B7:F2:E1:3E:DB";
        String dp1_ans = "00:C7:1D:94:24:39:D1:D2:89:C0:6E:36:DF:9A:11:6C:E2:23:44:6D:15:F6:16:97:7E:F9:E6:84:9B:F9:2D:B0:5B";
        String dq1_ans = "32:CC:36:AD:05:46:50:12:75:8A:0A:3A:E9:CC:F2:73:E3:0D:A8:B4:44:C9:C7:FA:CF:46:DE:B1:E1:B7:71:27";
        String qInv_ans = "00:91:7C:10:EF:24:18:0F:D3:4A:C3:D0:14:89:4E:34:92:A2:E6:D6:39:07:38:30:10:01:A1:5E:AF:DE:32:1B:41";
        URL resource = getClass().getClassLoader().getResource("./512/private_key.pem");
        File file;
        Rsa rsa = new Rsa();
        try {
            file = new File(resource.toURI());
            RSAPrivateKey rsaPrivateKey = rsa.readPrivateKey(file);

            // RSA public, private key
            BigInteger m = rsaPrivateKey.getModulus();
            BigInteger e = rsaPrivateKey.getPublicExponent();
            BigInteger d = rsaPrivateKey.getPrivateExponent();

            // RSA private crt key
            BigInteger p = rsaPrivateKey.getPrime1();         // Prime P
            BigInteger q = rsaPrivateKey.getPrime2();         // Prime Q
            BigInteger dp1 = rsaPrivateKey.getExponent1();    // Prime Exponent P
            BigInteger dq1 = rsaPrivateKey.getExponent2();    // Prime Exponent Q
            BigInteger qInv = rsaPrivateKey.getCoefficient(); // coefficient


            assertEquals(m_ans, toHex(m.toByteArray(), ":"));
            assertEquals(e_ans, toHex(e.toByteArray(), ":"));
            assertEquals(d_ans, toHex(d.toByteArray(), ":"));

            assertEquals(p_ans, toHex(p.toByteArray(), ":"));
            assertEquals(q_ans, toHex(q.toByteArray(), ":"));
            assertEquals(dp1_ans, toHex(dp1.toByteArray(), ":"));
            assertEquals(dq1_ans, toHex(dq1.toByteArray(), ":"));
            assertEquals(qInv_ans, toHex(qInv.toByteArray(), ":"));


        } catch (Exception e) {
            throw new RuntimeException(e.toString());
        }
    }

    @Test
    public void rsa_test_002() {
        // pem parse online: https://8gwifi.org/PemParserFunctions.jsp

        String m_ans = "00:E0:63:FD:FA:2F:3B:A5:A7:6D:0A:82:34:AB:03:04:" +
                "C1:9F:E8:69:05:13:2F:11:22:1E:7A:8A:1F:88:E8:FF:" +
                "1D:89:2D:7B:1D:88:B3:0E:D4:2E:34:5D:1B:3C:09:34:" +
                "EC:56:44:E0:98:0B:20:52:23:03:AA:42:62:56:05:61:61";
        String e_ans = "01:00:01";

        URL resource = getClass().getClassLoader().getResource("./512/public_key.pem");
        File file;
        Rsa rsa = new Rsa();
        try {
            file = new File(resource.toURI());
            RSAPublicKey rsaPublicKey = rsa.readPublicKey(file);

            // RSA public, private key
            BigInteger m = rsaPublicKey.getModulus();
            BigInteger e = rsaPublicKey.getPublicExponent();

            assertEquals(m_ans, toHex(m.toByteArray(), ":"));
            assertEquals(e_ans, toHex(e.toByteArray(), ":"));

        } catch (Exception e) {
            throw new RuntimeException(e.toString());
        }
    }
}
