package com.github.lechandonga.zerotrustdevicegatewayjava.store;

import com.github.lechandonga.zerotrustdevicegatewayjava.domain.DeviceIdentity;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * 设备身份存储。putIfAbsent 保证重复登记不覆盖已有身份与公钥。
 */
@Component
public class DeviceStore {

    private final ConcurrentMap<String, DeviceIdentity> devices = new ConcurrentHashMap<>();

    public Optional<DeviceIdentity> find(String deviceId) {
        return Optional.ofNullable(devices.get(deviceId));
    }

    /** 仅当设备不存在时写入；已存在则返回 false，绝不覆盖。 */
    public boolean registerIfAbsent(DeviceIdentity identity) {
        return devices.putIfAbsent(identity.deviceId(), identity) == null;
    }

    public void replace(DeviceIdentity identity) {
        devices.put(identity.deviceId(), identity);
    }

    public int size() {
        return devices.size();
    }
}
