package com.rookie.bigdata.authorization;

import jakarta.annotation.Nullable;
import org.springframework.security.core.Transient;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.Map;

/**
 * @Author rookie
 * @Description 设备码模式token
 * @Date 2024/5/8 18:03
 * @Version 1.0
 */
@Transient
public class DeviceClientAuthenticationToken extends OAuth2ClientAuthenticationToken {
    public DeviceClientAuthenticationToken(String clientId, ClientAuthenticationMethod clientAuthenticationMethod,
                                           @Nullable Object credentials, @Nullable Map<String, Object> additionalParameters) {
        super(clientId, clientAuthenticationMethod, credentials, additionalParameters);
    }

    public DeviceClientAuthenticationToken(RegisteredClient registeredClient, ClientAuthenticationMethod clientAuthenticationMethod,
                                           @Nullable Object credentials) {
        super(registeredClient, clientAuthenticationMethod, credentials);
    }
}
