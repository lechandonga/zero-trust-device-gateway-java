package com.example.ztgw.service;

import com.example.ztgw.error.ApiException;
import com.example.ztgw.model.DeviceIdentity;
import com.example.ztgw.store.GatewayStore;

final class DeviceIdentityRequires {

    private DeviceIdentityRequires() {
    }

    static DeviceIdentity requireEnrolled(GatewayStore store, String deviceId) {
        DeviceIdentity identity = store.getDevice(deviceId);
        if (identity == null) {
            throw ApiException.notFound("DEVICE_NOT_ENROLLED",
                    "device is not registered; enrollment is required first");
        }
        return identity;
    }
}
