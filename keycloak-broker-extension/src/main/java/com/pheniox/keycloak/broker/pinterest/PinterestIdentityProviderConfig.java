package com.pheniox.keycloak.broker.pinterest;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

public class PinterestIdentityProviderConfig extends OAuth2IdentityProviderConfig {

    public static final String DEFAULT_AUTH_URL = "https://www.pinterest.com/oauth/";
    public static final String DEFAULT_TOKEN_URL = "https://api.pinterest.com/v5/oauth/token";
    public static final String DEFAULT_USERINFO_URL = "https://api.pinterest.com/v5/user_account";
    public static final String DEFAULT_SCOPE = "boards:read,boards:write,pins:read,pins:write,user_accounts:read";

    public static final String CONF_BROKER_HANDOFF_URL = "brokerHandoffUrl";
    public static final String CONF_BROKER_HANDOFF_SECRET = "brokerHandoffSecret";
    public static final String CONF_CONTINUOUS_REFRESH = "continuousRefresh";

    public PinterestIdentityProviderConfig(IdentityProviderModel model) {
        super(model);
        initDefaults();
    }

    public PinterestIdentityProviderConfig() {
        super();
        initDefaults();
    }

    private void initDefaults() {
        if (getAuthorizationUrl() == null || getAuthorizationUrl().isBlank()) {
            setAuthorizationUrl(DEFAULT_AUTH_URL);
        }
        if (getTokenUrl() == null || getTokenUrl().isBlank()) {
            setTokenUrl(DEFAULT_TOKEN_URL);
        }
        if (getUserInfoUrl() == null || getUserInfoUrl().isBlank()) {
            setUserInfoUrl(DEFAULT_USERINFO_URL);
        }
        if (getDefaultScope() == null || getDefaultScope().isBlank()) {
            setDefaultScope(DEFAULT_SCOPE);
        }
        setEnabled(true);
        // Generic Keycloak provider token persistence must be explicitly disabled
        setStoreToken(false);
    }

    public String getBrokerHandoffUrl() {
        return getConfig().get(CONF_BROKER_HANDOFF_URL);
    }

    public void setBrokerHandoffUrl(String url) {
        getConfig().put(CONF_BROKER_HANDOFF_URL, url);
    }

    public String getBrokerHandoffSecret() {
        return getConfig().get(CONF_BROKER_HANDOFF_SECRET);
    }

    public void setBrokerHandoffSecret(String secret) {
        getConfig().put(CONF_BROKER_HANDOFF_SECRET, secret);
    }

    public boolean isContinuousRefresh() {
        return Boolean.parseBoolean(getConfig().getOrDefault(CONF_CONTINUOUS_REFRESH, "true"));
    }

    public void setContinuousRefresh(boolean continuousRefresh) {
        getConfig().put(CONF_CONTINUOUS_REFRESH, String.valueOf(continuousRefresh));
    }
}
