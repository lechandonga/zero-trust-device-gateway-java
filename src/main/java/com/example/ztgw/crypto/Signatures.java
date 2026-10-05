package com.example.ztgw.crypto;

import com.example.ztgw.error.ApiException;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Ed25519 signatures over an explicit canonical string, so the exact bytes
 * that were signed are reconstructable by both sides.
 */
public final class Signatures {

    public static final String KEY_ALGORITHM = "Ed25519";

    private Signatures() {
    }

    public static String attestPayload(String challengeId, String nonce, String measurement) {
        return "ZTG-ATTEST|1|" + challengeId + "|" + nonce + "|" + measurement;
    }

    public static String rotationPayload(String challengeId, String nonce,
                                         String oldKeyFingerprint, String newKeyFingerprint) {
        return "ZTG-ROTATE|1|" + challengeId + "|" + nonce + "|" + oldKeyFingerprint + "|" + newKeyFingerprint;
    }

    public static String sign(PrivateKey privateKey, String payload) {
        try {
            Signature signature = Signature.getInstance(KEY_ALGORITHM);
            signature.initSign(privateKey);
            signature.update(payload.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(signature.sign());
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new IllegalStateException("signing failed", e);
        }
    }

    public static PublicKey parsePublicKey(String x509Base64) {
        try {
            byte[] der = Base64.getDecoder().decode(x509Base64);
            return KeyFactory.getInstance(KEY_ALGORITHM).generatePublic(new X509EncodedKeySpec(der));
        } catch (IllegalArgumentException | InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw ApiException.badRequest("INVALID_PUBLIC_KEY", "public key is not a valid X.509 Ed25519 key");
        }
    }

    public static PublicKey parsePublicKeyBytes(byte[] der) {
        try {
            return KeyFactory.getInstance(KEY_ALGORITHM).generatePublic(new X509EncodedKeySpec(der));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw ApiException.badRequest("INVALID_PUBLIC_KEY", "public key is not a valid X.509 Ed25519 key");
        }
    }

    public static PrivateKey parsePrivateKey(String pkcs8Base64) {
        try {
            byte[] der = Base64.getDecoder().decode(pkcs8Base64);
            return KeyFactory.getInstance(KEY_ALGORITHM).generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (IllegalArgumentException | InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw ApiException.badRequest("INVALID_PRIVATE_KEY", "private key is not a valid PKCS#8 Ed25519 key");
        }
    }

    public static boolean verify(PublicKey publicKey, String payload, String signatureBase64) {
        try {
            Signature signature = Signature.getInstance(KEY_ALGORITHM);
            signature.initVerify(publicKey);
            signature.update(payload.getBytes(StandardCharsets.UTF_8));
            return signature.verify(Base64.getDecoder().decode(signatureBase64));
        } catch (IllegalArgumentException | InvalidKeyException | SignatureException e) {
            return false;
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Ed25519 unavailable", e);
        }
    }
}
