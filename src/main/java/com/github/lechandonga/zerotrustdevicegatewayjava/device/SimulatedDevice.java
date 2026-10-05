package com.github.lechandonga.zerotrustdevicegatewayjava.device;

import com.github.lechandonga.zerotrustdevicegatewayjava.crypto.KeyIds;
import com.github.lechandonga.zerotrustdevicegatewayjava.crypto.KeyMaterial;
import com.github.lechandonga.zerotrustdevicegatewayjava.crypto.Signatures;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.spec.ECGenParameterSpec;

import static com.github.lechandonga.zerotrustdevicegatewayjava.crypto.Signatures.EC;
import static com.github.lechandonga.zerotrustdevicegatewayjava.crypto.Signatures.RSA;

/**
 * 用本地生成的密钥对模拟真实设备侧能力（TPM/安全元件的软件替身）：
 * <ul>
 *   <li>本地生成并持有私钥，只把公钥提交给网关；</li>
 *   <li>本地维护“当前密钥”和“上一版密钥”，以模拟轮换过渡期；</li>
 *   <li>本地给出固件度量值并对挑战负载签名。</li>
 * </ul>
 * 全程不接触任何外部服务、真实硬件或外部凭据。
 */
public class SimulatedDevice {

    private final String deviceId;
    private String firmwareMeasurement;

    private KeyMaterial activePublic;
    private PrivateKey activePrivate;
    private KeyMaterial previousPublic;
    private PrivateKey previousPrivate;

    public SimulatedDevice(String deviceId, String firmwareMeasurement) {
        this.deviceId = deviceId;
        this.firmwareMeasurement = firmwareMeasurement;
        generateActive(EC);
    }

    private void generateActive(String algorithm) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
            if (EC.equals(algorithm)) {
                generator.initialize(new ECGenParameterSpec("secp256r1"));
            } else {
                generator.initialize(2048);
            }
            KeyPair pair = generator.generateKeyPair();
            byte[] spki = pair.getPublic().getEncoded();
            this.activePublic = new KeyMaterial(KeyIds.of(spki), algorithm, pair.getPublic(), spki);
            this.activePrivate = pair.getPrivate();
        } catch (Exception e) {
            throw new IllegalStateException("failed to generate device key pair", e);
        }
    }

    public String deviceId() {
        return deviceId;
    }

    public KeyMaterial activePublic() {
        return activePublic;
    }

    public KeyMaterial previousPublic() {
        return previousPublic;
    }

    public String firmwareMeasurement() {
        return firmwareMeasurement;
    }

    /** 模拟设备刷写/度量变化。 */
    public void updateFirmwareMeasurement(String measurement) {
        this.firmwareMeasurement = measurement;
    }

    /** 本地密钥轮换：当前密钥降为上一版（宽限期内仍可证明），生成全新当前密钥。 */
    public KeyMaterial rotateKey() {
        return rotateKey(EC);
    }

    public KeyMaterial rotateKey(String algorithm) {
        this.previousPublic = activePublic;
        this.previousPrivate = activePrivate;
        generateActive(algorithm);
        return activePublic;
    }

    /** 宽限期结束，设备本地销毁旧私钥。 */
    public void destroyPreviousKey() {
        this.previousPublic = null;
        this.previousPrivate = null;
    }

    /** 用当前私钥签名。 */
    public byte[] signWithActive(byte[] payload) {
        return sign(activePrivate, activePublic.algorithm(), payload);
    }

    /** 宽限期内用旧私钥签名（模拟尚未完成切换的设备组件）。 */
    public byte[] signWithPrevious(byte[] payload) {
        if (previousPrivate == null) {
            throw new IllegalStateException("previous key already destroyed");
        }
        return sign(previousPrivate, previousPublic.algorithm(), payload);
    }

    private byte[] sign(PrivateKey privateKey, String algorithm, byte[] payload) {
        try {
            return Signatures.sign(privateKey, payload);
        } catch (Exception e) {
            throw new IllegalStateException("device signing failed", e);
        }
    }
}
