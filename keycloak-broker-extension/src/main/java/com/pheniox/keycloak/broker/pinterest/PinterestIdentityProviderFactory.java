package com.pheniox.keycloak.broker.pinterest;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

public class PinterestIdentityProviderFactory extends AbstractIdentityProviderFactory<PinterestIdentityProvider> {

    public static final String PROVIDER_ID = "pinterest";

    @Override
    public String getName() {
        return "Pinterest";
    }

    @Override
    public PinterestIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new PinterestIdentityProvider(session, new PinterestIdentityProviderConfig(model));
    }

    @Override
    public PinterestIdentityProviderConfig createConfig() {
        return new PinterestIdentityProviderConfig();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
