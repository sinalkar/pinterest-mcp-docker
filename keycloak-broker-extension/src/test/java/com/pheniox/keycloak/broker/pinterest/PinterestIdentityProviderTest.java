package com.pheniox.keycloak.broker.pinterest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.models.KeycloakSession;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

public class PinterestIdentityProviderTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private KeycloakSession session;
    private PinterestIdentityProviderConfig config;
    private PinterestIdentityProvider provider;
    private org.keycloak.sessions.AuthenticationSessionModel auth;
    private java.util.Map<String, String> notes;
    private org.keycloak.models.RealmModel realm;

    @BeforeEach
    public void setup() {
        session = mock(KeycloakSession.class);
        config = new PinterestIdentityProviderConfig();
        config.setEnabled(true);
        config.setClientId("test-pinterest-client");
        config.setClientSecret("test-secret");
        config.setAlias("pinterest");
        provider = new PinterestIdentityProvider(session, config);
        auth = mock(org.keycloak.sessions.AuthenticationSessionModel.class);
        var keycloakContext = mock(org.keycloak.models.KeycloakContext.class);
        when(session.getContext()).thenReturn(keycloakContext);
        when(keycloakContext.getAuthenticationSession()).thenReturn(auth);
        var root = mock(org.keycloak.sessions.RootAuthenticationSessionModel.class);
        when(root.getId()).thenReturn("browser-session");
        when(auth.getParentSession()).thenReturn(root);
        when(auth.getTabId()).thenReturn("tab-one");
        var client = mock(org.keycloak.models.ClientModel.class);
        when(client.getId()).thenReturn("chatgpt-client");
        when(auth.getClient()).thenReturn(client);
        when(auth.getRedirectUri()).thenReturn("https://chatgpt.com/connector_platform_oauth_redirect");
        realm = mock(org.keycloak.models.RealmModel.class);
        when(realm.getAttribute("frontendUrl")).thenReturn("https://auth.example.com");
        when(realm.getName()).thenReturn("pinterest");
        when(auth.getRealm()).thenReturn(realm);
        notes = new java.util.HashMap<>();
        doAnswer(i -> { notes.put(i.getArgument(0), i.getArgument(1)); return null; })
                .when(auth).setAuthNote(anyString(), anyString());
        when(auth.getAuthNote(anyString())).thenAnswer(i -> notes.get(i.getArgument(0)));
        provider.initializeTransaction(auth);
    }

    @Test
    public void testConfigDefaultsHaveStoreTokenDisabled() {
        assertFalse(config.isStoreToken(), "Generic Keycloak token storage must be disabled");
        assertEquals("https://www.pinterest.com/oauth/", config.getAuthorizationUrl());
        assertEquals("https://api.pinterest.com/v5/oauth/token", config.getTokenUrl());
        assertEquals("https://api.pinterest.com/v5/user_account", config.getUserInfoUrl());
        assertTrue(config.getDefaultScope().contains("boards:read"));
    }

    @Test
    public void testExtractIdentityValidNumericId() throws Exception {
        String json = """
            {
                "id": "159879012345678901",
                "username": "paboratory",
                "account_type": "BUSINESS"
            }
            """;
        JsonNode profile = MAPPER.readTree(json);

        BrokeredIdentityContext context = provider.extractIdentityFromProfile(null, profile);

        assertNotNull(context);
        assertEquals("159879012345678901", context.getId());
        assertEquals("159879012345678901", context.getUsername());
        assertEquals("159879012345678901", context.getModelUsername());
        assertNull(context.getEmail(), "Email must never be set on Pinterest identity context");
        assertEquals("paboratory", context.getUserAttribute("pinterest_username"));
        assertEquals("BUSINESS", context.getUserAttribute("pinterest_account_type"));
    }

    @Test
    public void testExtractIdentityMissingIdThrowsException() throws Exception {
        String json = """
            {
                "username": "paboratory",
                "account_type": "BUSINESS"
            }
            """;
        JsonNode profile = MAPPER.readTree(json);

        IdentityBrokerException ex = assertThrows(IdentityBrokerException.class, () -> {
            provider.extractIdentityFromProfile(null, profile);
        });
        assertTrue(ex.getMessage().contains("missing required 'id' field"));
    }

    @Test
    public void testExtractIdentityNonNumericIdThrowsException() throws Exception {
        String json = """
            {
                "id": "invalid_alpha_numeric_id",
                "username": "paboratory"
            }
            """;
        JsonNode profile = MAPPER.readTree(json);

        IdentityBrokerException ex = assertThrows(IdentityBrokerException.class, () -> {
            provider.extractIdentityFromProfile(null, profile);
        });
        assertTrue(ex.getMessage().contains("Invalid Pinterest user account id format"));
    }

    @Test
    public void testHmacSha256SignatureComputation() throws Exception {
        String secret = "super-secret-key-12345";
        String canonicalData = "POST\n/internal/credential-ingress\n1700000000\nnonce123\ndigest456";

        String signature = PinterestIdentityProvider.hmacSha256Hex(secret, canonicalData);
        assertNotNull(signature);
        assertEquals(64, signature.length(), "HMAC-SHA256 hex string must be 64 characters");

        // Verify repeatability
        String signature2 = PinterestIdentityProvider.hmacSha256Hex(secret, canonicalData);
        assertEquals(signature, signature2);
    }
    @Test
    public void testMissingHandoffFailsClosed() {
        assertThrows(IdentityBrokerException.class,
                () -> provider.sendHandoff(java.util.Map.of("transaction_id", "test"), "staged"));
        config.setBrokerHandoffUrl("https://vault.internal/credentials");
        assertThrows(IdentityBrokerException.class,
                () -> provider.sendHandoff(java.util.Map.of("transaction_id", "test"), "staged"));
    }

    @Test
    public void testUnsafeHandoffDestinationsFailBeforeCredentialsAreRead() {
        config.setBrokerHandoffSecret("test-secret");
        for (String url : new String[] {"http://vault.internal/credentials",
                "https://user:password@vault.internal/credentials",
                "https://vault.internal/credentials?secret=value",
                "https://vault.internal/credentials#fragment", "invalid uri"}) {
            config.setBrokerHandoffUrl(url);
            assertThrows(IdentityBrokerException.class,
                    () -> provider.sendHandoff(java.util.Map.of("transaction_id", "test"), "staged"));
        }
    }
    private String validTokenResponse() {
        return """
                {"access_token":"sentinel-access", "refresh_token":"sentinel-refresh",
                 "token_type":"bearer", "scope":"user_accounts:read,pins:read",
                 "expires_in":3600, "refresh_token_expires_in":5184000}
                """;
    }

    @Test
    public void testCallbackLooksUpAccountAndPreservesGrantedMetadata() {
        PinterestIdentityProvider testProvider = new PinterestIdentityProvider(session, config) {
            @Override
            protected JsonNode lookupAccount(String accessToken) throws java.io.IOException {
                assertEquals("sentinel-access", accessToken);
                return MAPPER.readTree("{\"id\":\"123456789\"}");
            }
            @Override
            protected void sendHandoff(java.util.Map<String, Object> payload, String status) {
                assertEquals("staged", status);
                assertEquals("stage", payload.get("action"));
                var tokens = (java.util.Map<?, ?>) payload.get("tokens");
                assertEquals("sentinel-refresh", tokens.get("refresh_token"));
                assertEquals(3600L, tokens.get("expires_in"));
                assertEquals("user_accounts:read,pins:read", tokens.get("scope"));
            }
        };
        BrokeredIdentityContext context = testProvider.getFederatedIdentity(validTokenResponse());
        assertEquals("123456789", context.getId());
        assertNull(context.getToken());
        assertEquals(java.util.Set.of(PinterestIdentityProvider.CONTEXT_REFERENCE), context.getContextData().keySet());
        context.setAuthenticationSession(auth);
        org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext
                .serialize(context).saveToAuthenticationSession(auth, "serialized-broker");
        String serialized = notes.get("serialized-broker");
        assertNotNull(serialized);
        assertFalse(serialized.contains("sentinel-access"));
        assertFalse(serialized.contains("sentinel-refresh"));
        assertFalse(serialized.contains("access_token"));
    }

    @Test
    public void testMalformedTokensFailBeforeAccountRequestWithoutLeakingSecrets() {
        PinterestIdentityProvider testProvider = new PinterestIdentityProvider(session, config) {
            @Override
            protected JsonNode lookupAccount(String accessToken) {
                fail("Malformed tokens must not trigger an account request");
                return null;
            }
        };
        for (String response : new String[] {"sentinel-secret-not-json", "null", "[]",
                "{\"error\":\"sentinel-secret\"}",
                validTokenResponse().replace("3600", "-1"),
                validTokenResponse().replace("3600", "1.5"),
                validTokenResponse().replace("user_accounts:read,pins:read", "pins:read"),
                validTokenResponse().replace("bearer", "mac"),
                validTokenResponse().replace("sentinel-refresh", "")}) {
            var error = assertThrows(IdentityBrokerException.class,
                    () -> testProvider.getFederatedIdentity(response));
            assertFalse(error.toString().contains("sentinel"));
            assertNull(error.getCause());
        }
    }

    @Test
    public void testLookupFailureDoesNotExposeProviderDetails() {
        PinterestIdentityProvider testProvider = new PinterestIdentityProvider(session, config) {
            @Override
            protected JsonNode lookupAccount(String accessToken) throws java.io.IOException {
                throw new java.io.IOException("sentinel-access in transport failure");
            }
        };
        var error = assertThrows(IdentityBrokerException.class,
                () -> testProvider.getFederatedIdentity(validTokenResponse()));
        assertFalse(error.toString().contains("sentinel"));
        assertNull(error.getCause());
    }
    @Test
    public void testStorageOutageAbortsIdentityCreation() {
        var testProvider = new PinterestIdentityProvider(session, config) {
            @Override
            protected JsonNode lookupAccount(String access) throws java.io.IOException {
                return MAPPER.readTree("{\"id\":\"123456789\"}");
            }
            @Override
            protected void sendHandoff(java.util.Map<String, Object> payload, String status) {
                throw new IdentityBrokerException("Storage unavailable");
            }
        };
        assertThrows(IdentityBrokerException.class,
                () -> testProvider.getFederatedIdentity(validTokenResponse()));
        assertFalse(notes.toString().contains("sentinel"));
    }

    @Test
    public void testCompletionUsesReferenceAndFinalizedSubjectOnly() {
        var requests = new java.util.ArrayList<java.util.Map<String, Object>>();
        var testProvider = new PinterestIdentityProvider(session, config) {
            @Override
            protected void sendHandoff(java.util.Map<String, Object> payload, String status) {
                assertEquals("completed", status);
                requests.add(payload);
            }
        };
        var context = new BrokeredIdentityContext("123456789", config);
        context.setAuthenticationSession(auth);
        context.getContextData().put(PinterestIdentityProvider.CONTEXT_REFERENCE,
                notes.get(PinterestIdentityProvider.TRANSACTION_NOTE));
        var user = mock(org.keycloak.models.UserModel.class);
        when(user.getId()).thenReturn("finalized-user");
        testProvider.importNewUser(session, realm, user, context);
        testProvider.updateBrokeredUser(session, realm, user, context);
        assertEquals(requests.get(0), requests.get(1));
        assertEquals("finalized-user", requests.get(0).get("subject"));
        assertFalse(requests.get(0).containsKey("tokens"));
        context.getContextData().put(PinterestIdentityProvider.CONTEXT_REFERENCE, "foreign-reference");
        assertThrows(IdentityBrokerException.class,
                () -> testProvider.importNewUser(session, realm, user, context));
        assertEquals(2, requests.size());
    }
}
