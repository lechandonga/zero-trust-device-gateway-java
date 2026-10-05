package com.github.lechandonga.zerotrustdevicegatewayjava.web;

import com.github.lechandonga.zerotrustdevicegatewayjava.service.RotationService;
import com.github.lechandonga.zerotrustdevicegatewayjava.web.dto.Requests;
import com.github.lechandonga.zerotrustdevicegatewayjava.web.dto.Views;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/devices/{deviceId}/keys")
public class RotationController {

    private final RotationService rotationService;

    public RotationController(RotationService rotationService) {
        this.rotationService = rotationService;
    }

    /** 用旧私钥授权的挑战签名轮换到新公钥，进入宽限过渡期。 */
    @PostMapping("/rotate")
    public Views.DeviceView rotate(@PathVariable String deviceId,
                                   @RequestBody Requests.RotateRequest request) {
        return Views.DeviceView.of(rotationService.rotate(
                request.challengeId(), deviceId, request.newKeyAlgorithm(),
                request.newPublicKeySpki(), request.signature(), request.gracePeriod()));
    }

    /** 提前结束过渡期，旧公钥立即作废。 */
    @PostMapping("/finalize")
    public Views.DeviceView finalize(@PathVariable String deviceId) {
        return Views.DeviceView.of(rotationService.finalizeRotation(deviceId));
    }
}
