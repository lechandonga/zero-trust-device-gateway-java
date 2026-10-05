package com.github.lechandonga.zerotrustdevicegatewayjava.web;

import com.github.lechandonga.zerotrustdevicegatewayjava.service.EnrollmentService;
import com.github.lechandonga.zerotrustdevicegatewayjava.web.dto.Requests;
import com.github.lechandonga.zerotrustdevicegatewayjava.web.dto.Views;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/enrollment")
public class EnrollmentController {

    private final EnrollmentService enrollmentService;

    public EnrollmentController(EnrollmentService enrollmentService) {
        this.enrollmentService = enrollmentService;
    }

    /** 管理侧签发一次性入网令牌。 */
    @PostMapping("/tokens")
    @ResponseStatus(HttpStatus.CREATED)
    public Views.TokenView issueToken(@RequestBody Requests.IssueTokenRequest request) {
        return Views.TokenView.of(enrollmentService.issueToken(
                request.token(), request.expectedDeviceId(), request.ttl()));
    }

    /** 设备凭一次性令牌换取身份绑定。 */
    @PostMapping("/enroll")
    @ResponseStatus(HttpStatus.CREATED)
    public Views.DeviceView enroll(@RequestBody Requests.EnrollRequest request) {
        return Views.DeviceView.of(enrollmentService.enroll(
                request.token(), request.deviceId(),
                request.keyAlgorithm(), request.publicKeySpki()));
    }
}
