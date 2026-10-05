package com.github.lechandonga.zerotrustdevicegatewayjava.crypto;

import java.security.PublicKey;

/**
 * 一把设备密钥的元数据：密钥标识、公钥与 X.509 SubjectPublicKeyInfo 编码。
 */
public record KeyMaterial(String keyId, String algorithm, PublicKey publicKey, byte[] spki) {
}
