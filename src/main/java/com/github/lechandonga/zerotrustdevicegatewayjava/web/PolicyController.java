package com.github.lechandonga.zerotrustdevicegatewayjava.web;

import com.github.lechandonga.zerotrustdevicegatewayjava.service.PolicyService;
import com.github.lechandonga.zerotrustdevicegatewayjava.web.dto.Requests;
import com.github.lechandonga.zerotrustdevicegatewayjava.web.dto.Views;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Set;

@RestController
@RequestMapping("/api/policy")
public class PolicyController {

    private final PolicyService policyService;

    public PolicyController(PolicyService policyService) {
        this.policyService = policyService;
    }

    /** 当前策略版本。 */
    @GetMapping("/current")
    public Views.PolicyView current() {
        return Views.PolicyView.of(policyService.current());
    }

    /** 历史版本（证据回指与审计）。 */
    @GetMapping("/versions")
    public Views.PolicyHistory history() {
        return new Views.PolicyHistory(policyService.history().values().stream()
                .map(Views.PolicyView::of).toList());
    }

    @GetMapping("/versions/{version}")
    public Views.PolicyView version(@PathVariable long version) {
        return Views.PolicyView.of(policyService.version(version));
    }

    /** 全量发布新基线 + 新吊销名单，版本号 +1。 */
    @PostMapping("/publish")
    public Views.PolicyView publish(@RequestBody Requests.PublishPolicyRequest request) {
        List<String> measurements = request.trustedMeasurements() == null
                ? List.of() : request.trustedMeasurements();
        List<String> revoked = request.revokedDevices() == null
                ? List.of() : request.revokedDevices();
        return Views.PolicyView.of(policyService.publish(
                Set.copyOf(measurements), Set.copyOf(revoked), request.note()));
    }

    /** 便捷吊销：在当前版本基础上把设备加入吊销名单并发布新版本。 */
    @PostMapping("/revoke")
    public Views.PolicyView revoke(@RequestBody Requests.RevokeRequest request) {
        return Views.PolicyView.of(policyService.revoke(request.deviceId(), request.note()));
    }

    /** 解除吊销（本地演示用）。 */
    @PostMapping("/unrevoke")
    public Views.PolicyView unrevoke(@RequestBody Requests.UnrevokeRequest request) {
        return Views.PolicyView.of(policyService.unrevoke(request.deviceId(), request.note()));
    }
}
