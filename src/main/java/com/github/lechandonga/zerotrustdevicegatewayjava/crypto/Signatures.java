package com.github.lechandonga.zerotrustdevicegatewayjava.crypto;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * 签名原语：本地模拟设备与服务端共用。
 * 支持 ECDSA(P-256) + SHA256（默认）与 RSA(2048+) + SHA256。
 */
public final class Signatures {

    public static final String EC = "EC";
    public static final String RSA = "RSA";

    private Signatures() {
    }

    public static String jcaAlgorithm(String keyAlgorithm) {
        return switch (keyAlgorithm) {
            case EC -> "SHA256withECDSA";
            case RSA -> "SHA256withRSA";
            default -> throw new IllegalArgumentException("unsupported key algorithm: " + keyAlgorithm);
        };
    }

    public static byte[] sign(PrivateKey privateKey, byte[] data) throws Exception {
        Signature signature = Signature.getInstance(jcaAlgorithm(privateKey.getAlgorithm()));
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    public static boolean verify(PublicKey publicKey, byte[] data, byte[] signed) {
        try {
            Signature signature = Signature.getInstance(jcaAlgorithm(publicKey.getAlgorithm()));
            signature.initVerify(publicKey);
            signature.update(data);
            return signature.verify(signed);
        } catch (Exception e) {
            return false;
        }
    }

    public static String toBase64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    public static byte[] fromBase64(String value) {
        return Base64.getDecoder().decode(value);
    }

    public static PublicKey parsePublicKey(String algorithm, String base64Spki) throws Exception {
        return KeyFactory.getInstance(algorithm)
                .generatePublic(new X509EncodedKeySpec(fromBase64(base64Spki)));
    }

    public static PrivateKey parsePrivateKey(String algorithm, byte[] pkcs8) throws Exception {
        return KeyFactory.getInstance(algorithm)
                .generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
    }
}
