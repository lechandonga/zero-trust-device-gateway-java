package com.github.lechandonga.zerotrustdevicegatewayjava.tests.support;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lechandonga.zerotrustdevicegatewayjava.crypto.Signatures;
import com.github.lechandonga.zerotrustdevicegatewayjava.device.SimulatedDevice;
import com.github.lechandonga.zerotrustdevicegatewayjava.device.SigningPayloads;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 全部业务测试的基类：随机端口启动完整 Web 栈，走真实 HTTP，
 * 设备侧使用 {@link SimulatedDevice} 本地密钥对完成签名。
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(BusinessLoggingExtension.class)
public abstract class ApiTestBase {

    protected static final ObjectMapper JSON = new ObjectMapper();

    @Autowired
    protected TestRestTemplate rest;

    protected static Map<String, Object> body(Object... keyValues) {
        if (keyValues.length % 2 != 0) {
            throw new IllegalArgumentException("key/values must be paired");
        }
        Map<String, Object> map = new LinkedHashMap<>();
        for (int i = 0; i < keyValues.length; i += 2) {
            map.put((String) keyValues[i], keyValues[i + 1]);
        }
        return map;
    }

    protected ResponseEntity<JsonNode> post(String path, Object requestBody) {
        return exchange(HttpMethod.POST, path, requestBody);
    }

    protected ResponseEntity<JsonNode> get(String path) {
        return exchange(HttpMethod.GET, path, null);
    }

    protected ResponseEntity<JsonNode> exchange(HttpMethod method, String path, Object requestBody) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<Object> entity = new HttpEntity<>(requestBody, headers);
        return rest.exchange(path, method, entity, JsonNode.class);
    }

    protected ResponseEntity<JsonNode> issueToken(String token, String expectedDevice) {
        return post("/api/enrollment/tokens",
                body("token", token, "expectedDeviceId", expectedDevice, "ttl", "PT2M"));
    }

    protected ResponseEntity<JsonNode> enroll(SimulatedDevice device, String token) {
        return post("/api/enrollment/enroll", body(
                "token", token,
                "deviceId", device.deviceId(),
                "keyAlgorithm", device.activePublic().algorithm(),
                "publicKeySpki", Signatures.toBase64(device.activePublic().spki())));
    }

    protected JsonNode challenge(String deviceId) {
        return post("/api/challenges", body("deviceId", deviceId)).getBody();
    }

    protected Map<String, Object> attestRequest(SimulatedDevice device, JsonNode challenge,
                                                boolean useActiveKey) {
        byte[] payload = SigningPayloads.attestation(
                device.deviceId(),
                challenge.get("nonce").asText(),
                device.firmwareMeasurement());
        byte[] signed = useActiveKey ? device.signWithActive(payload) : device.signWithPrevious(payload);
        String keyId = useActiveKey ? device.activePublic().keyId()
                : (device.previousPublic() != null ? device.previousPublic().keyId() : null);
        return body(
                "challengeId", challenge.get("challengeId").asText(),
                "deviceId", device.deviceId(),
                "measurement", device.firmwareMeasurement(),
                "keyId", keyId,
                "signature", Signatures.toBase64(signed));
    }

    protected Map<String, Object> attestRequestCustom(SimulatedDevice device, JsonNode challenge,
                                                      String measurement, byte[] signature,
                                                      String keyId) {
        return body(
                "challengeId", challenge.get("challengeId").asText(),
                "deviceId", device.deviceId(),
                "measurement", measurement,
                "keyId", keyId,
                "signature", signature == null ? null : Signatures.toBase64(signature));
    }
}
