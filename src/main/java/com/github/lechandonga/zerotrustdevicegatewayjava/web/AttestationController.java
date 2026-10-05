package com.github.lechandonga.zerotrustdevicegatewayjava.web;

import com.github.lechandonga.zerotrustdevicegatewayjava.domain.AdmissionSession;
import com.github.lechandonga.zerotrustdevicegatewayjava.service.AttestationService;
import com.github.lechandonga.zerotrustdevicegatewayjava.service.ChallengeService;
import com.github.lechandonga.zerotrustdevicegatewayjava.service.SessionService;
import com.github.lechandonga.zerotrustdevicegatewayjava.store.PolicyStore;
import com.github.lechandonga.zerotrustdevicegatewayjava.web.dto.Requests;
import com.github.lechandonga.zerotrustdevicegatewayjava.web.dto.Views;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class AttestationController {

    private final ChallengeService challengeService;
    private final AttestationService attestationService;
    private final SessionService sessionService;
    private final PolicyStore policyStore;

    public AttestationController(ChallengeService challengeService,
                                 AttestationService attestationService,
                                 SessionService sessionService,
                                 PolicyStore policyStore) {
        this.challengeService = challengeService;
        this.attestationService = attestationService;
        this.sessionService = sessionService;
        this.policyStore = policyStore;
    }

    /** 下发一次性、有时效的挑战（响应中带钉住的策略版本）。 */
    @PostMapping("/challenges")
    @ResponseStatus(HttpStatus.CREATED)
    public Views.ChallengeView issueChallenge(@RequestBody Requests.ChallengeRequest request) {
        return Views.ChallengeView.of(challengeService.issue(request.deviceId()));
    }

    /** 设备提交签名证明，换取短期准入会话。 */
    @PostMapping("/attestations")
    @ResponseStatus(HttpStatus.CREATED)
    public Views.SessionView attest(@RequestBody Requests.AttestRequest request) {
        AdmissionSession session = attestationService.attest(
                request.challengeId(), request.deviceId(), request.measurement(),
                request.signature(), request.keyId(), request.sessionTtl());
        return Views.SessionView.admitted(session, policyStore.current().version());
    }

    /** 校验已发放会话是否仍有效（过期或设备被吊销则立即拒绝）。 */
    @GetMapping("/sessions/{sessionId}")
    public Views.SessionView getSession(@PathVariable String sessionId) {
        AdmissionSession session = sessionService.requireValid(sessionId);
        return Views.SessionView.admitted(session, policyStore.current().version());
    }
}
