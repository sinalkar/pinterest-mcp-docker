package com.pheniox.keycloak.broker.pinterest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;
import java.util.UUID;

public class PinterestIdentityProvider extends AbstractOAuth2IdentityProvider<PinterestIdentityProviderConfig> {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    public static final String CONTEXT_REFERENCE = "pinterest_pending_reference";
    static final String TRANSACTION_NOTE = "pinterest_transaction";
    static final String DEADLINE_NOTE = "pinterest_deadline";

    public PinterestIdentityProvider(KeycloakSession session, PinterestIdentityProviderConfig config) {
        super(session, config);
    }

    @Override
    protected String getDefaultScopes() {
        return getConfig().getDefaultScope();
    }

    @Override
    public BrokeredIdentityContext getFederatedIdentity(String response) {
        // Do not delegate to the base parser: its failures can include the raw response.
        try {
            if (response == null || response.length() > 65536) {
                throw new IdentityBrokerException("Invalid Pinterest token response");
            }
            JsonNode tokens = MAPPER.readTree(response);
            if (tokens == null || !tokens.isObject() || tokens.has("error")) {
                throw new IdentityBrokerException("Pinterest token exchange failed");
            }
            String access = requiredText(tokens, "access_token");
            String refresh = requiredText(tokens, "refresh_token");
            if (!"bearer".equalsIgnoreCase(requiredText(tokens, "token_type"))) {
                throw new IdentityBrokerException("Unsupported Pinterest token type");
            }
            String scope = requiredText(tokens, "scope");
            if (!java.util.Arrays.asList(scope.split("[,\\s]+")).contains("user_accounts:read")) {
                throw new IdentityBrokerException("Pinterest account permission is required");
            }
            long expiry = requiredExpiry(tokens, "expires_in");
            long refreshExpiry = requiredExpiry(tokens, "refresh_token_expires_in");
            BrokeredIdentityContext context = extractIdentityFromProfile(null, lookupAccount(access));
            AuthenticationSessionModel auth = session.getContext().getAuthenticationSession();
            Map<String, Object> payload = transactionPayload(auth, context.getId());
            payload.put("action", "stage");
            payload.put("expires_at", Long.parseLong(auth.getAuthNote(DEADLINE_NOTE)));
            payload.put("account_username", context.getUserAttribute("pinterest_username"));
            payload.put("account_type", context.getUserAttribute("pinterest_account_type"));
            payload.put("tokens", Map.of("access_token", access, "refresh_token", refresh,
                    "expires_in", expiry, "refresh_token_expires_in", refreshExpiry, "scope", scope));
            sendHandoff(payload, "staged");
            context.getContextData().put(CONTEXT_REFERENCE, payload.get("transaction_id"));
            return context;
        } catch (IdentityBrokerException e) {
            throw e;
        } catch (Exception e) {
            throw new IdentityBrokerException("Invalid Pinterest authorization response");
        }
    }

    private static String requiredText(JsonNode node, String key) {
        JsonNode value = node.get(key);
        if (value == null || !value.isTextual() || value.asText().isBlank()
                || value.asText().chars().anyMatch(c -> c < 32 || c == 127)) {
            throw new IdentityBrokerException("Invalid Pinterest token metadata");
        }
        return value.asText();
    }

    private static long requiredExpiry(JsonNode node, String key) {
        JsonNode value = node.get(key);
        if (value == null || !value.isIntegralNumber() || !value.canConvertToLong()
                || value.asLong() <= 0 || value.asLong() > 315360000L) {
            throw new IdentityBrokerException("Invalid Pinterest token expiry");
        }
        return value.asLong();
    }

    protected JsonNode lookupAccount(String accessToken) throws IOException {
        // Pin the provider origin and reject redirects before sending credentials.
        if (!PinterestIdentityProviderConfig.DEFAULT_USERINFO_URL.equals(getConfig().getUserInfoUrl())) {
            throw new IdentityBrokerException("Unsupported Pinterest account endpoint");
        }
        var requestConfig = org.apache.http.client.config.RequestConfig.custom()
                .setConnectTimeout(10000).setSocketTimeout(10000)
                .setConnectionRequestTimeout(10000).setRedirectsEnabled(false).build();
        try (var client = org.apache.http.impl.client.HttpClients.custom()
                .setDefaultRequestConfig(requestConfig).disableRedirectHandling()
                .disableAutomaticRetries().build()) {
            var request = new org.apache.http.client.methods.HttpGet(
                    PinterestIdentityProviderConfig.DEFAULT_USERINFO_URL);
            request.setHeader("Authorization", "Bearer " + accessToken);
            request.setHeader("Accept", "application/json");
            try (var response = client.execute(request)) {
                if (response.getStatusLine().getStatusCode() != 200 || response.getEntity() == null) {
                    throw new IdentityBrokerException("Pinterest account lookup failed");
                }
                try (var stream = response.getEntity().getContent()) {
                    byte[] body = stream.readNBytes(65537);
                    if (body.length > 65536) {
                        throw new IdentityBrokerException("Pinterest account response too large");
                    }
                    return MAPPER.readTree(body);
                }
            }
        }
    }

    @Override
    protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event, JsonNode profile) {
        if (profile == null) {
            throw new IdentityBrokerException("Empty profile response from Pinterest");
        }

        JsonNode idNode = profile.get("id");
        if (idNode == null || idNode.asText().isBlank()) {
            throw new IdentityBrokerException("Pinterest user account response is missing required 'id' field");
        }

        String pinterestId = idNode.asText().trim();
        // Pinterest user account IDs are numeric 18-digit IDs
        if (!pinterestId.matches("^\\d+$")) {
            throw new IdentityBrokerException("Invalid Pinterest user account id format");
        }

        BrokeredIdentityContext user = new BrokeredIdentityContext(pinterestId, getConfig());
        user.setId(pinterestId);
        user.setUsername(pinterestId);
        user.setModelUsername(pinterestId);
        // Explicitly clear email to avoid auto-linking or email-based identity assumptions
        user.setEmail(null);

        JsonNode usernameNode = profile.get("username");
        if (usernameNode != null && !usernameNode.asText().isBlank()) {
            user.setUserAttribute("pinterest_username", usernameNode.asText());
        }
        JsonNode accountTypeNode = profile.get("account_type");
        if (accountTypeNode != null && !accountTypeNode.asText().isBlank()) {
            user.setUserAttribute("pinterest_account_type", accountTypeNode.asText());
        }

        user.setIdp(this);
        return user;
    }

    @Override
    public void importNewUser(KeycloakSession session, RealmModel realm, UserModel user, BrokeredIdentityContext context) {
        performCredentialHandoff(session, realm, user, context);
    }

    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user, BrokeredIdentityContext context) {
        performCredentialHandoff(session, realm, user, context);
    }

    @Override
    public jakarta.ws.rs.core.Response performLogin(AuthenticationRequest request) {
        initializeTransaction(request.getAuthenticationSession());
        return super.performLogin(request);
    }

    protected void initializeTransaction(AuthenticationSessionModel auth) {
        auth.setAuthNote(TRANSACTION_NOTE, UUID.randomUUID().toString());
        auth.setAuthNote(DEADLINE_NOTE, String.valueOf(Instant.now().getEpochSecond() + 300));
    }

    private Map<String, Object> transactionPayload(AuthenticationSessionModel auth, String account) {
        try {
            if (auth == null || auth.getAuthNote(TRANSACTION_NOTE) == null
                    || Long.parseLong(auth.getAuthNote(DEADLINE_NOTE)) <= Instant.now().getEpochSecond()) {
                throw new IdentityBrokerException("Pinterest login transaction expired or missing");
            }
            String binding = sha256Hex(MAPPER.writeValueAsBytes(java.util.List.of(
                    auth.getParentSession().getId(), auth.getTabId(),
                    auth.getClient().getId(), auth.getRedirectUri())));
            Map<String, Object> payload = new HashMap<>();
            payload.put("transaction_id", auth.getAuthNote(TRANSACTION_NOTE));
            payload.put("binding", binding);
            payload.put("issuer", getIssuerUrl(session, auth.getRealm()));
            payload.put("provider_account_id", account);
            return payload;
        } catch (IdentityBrokerException e) {
            throw e;
        } catch (Exception e) {
            throw new IdentityBrokerException("Invalid Pinterest login transaction");
        }
    }

    protected void performCredentialHandoff(KeycloakSession session, RealmModel realm,
                                             UserModel user, BrokeredIdentityContext context) {
        try {
            Map<String, Object> payload = transactionPayload(context.getAuthenticationSession(), context.getId());
            if (!payload.get("transaction_id").equals(context.getContextData().get(CONTEXT_REFERENCE))) {
                throw new IdentityBrokerException("Pinterest pending transaction mismatch");
            }
            payload.put("action", "complete");
            payload.put("subject", user.getId());
            sendHandoff(payload, "completed");
        } catch (IdentityBrokerException e) {
            throw e;
        } catch (Exception e) {
            throw new IdentityBrokerException("Failed to complete Pinterest login");
        }
    }

    protected void sendHandoff(Map<String, Object> payload, String expectedStatus) {
        try {
            String handoffUrl = getConfig().getBrokerHandoffUrl();
            String secret = getConfig().getBrokerHandoffSecret();
            if (handoffUrl == null || secret == null || secret.isBlank()) {
                throw new IdentityBrokerException("Broker handoff configuration missing");
            }
            java.net.URI destination = java.net.URI.create(handoffUrl);
            if (!"https".equalsIgnoreCase(destination.getScheme()) || destination.getHost() == null
                    || destination.getRawUserInfo() != null || destination.getRawQuery() != null
                    || destination.getRawFragment() != null
                    || !"/internal/credential-ingress".equals(destination.getRawPath())) {
                throw new IdentityBrokerException("Broker handoff requires the private HTTPS endpoint");
            }
            byte[] body = MAPPER.writeValueAsBytes(payload);
            String timestamp = String.valueOf(Instant.now().getEpochSecond());
            String nonce = UUID.randomUUID().toString().replace("-", "");
            String signature = hmacSha256Hex(secret, "POST\n" + destination.getRawPath()
                    + "\n" + timestamp + "\n" + nonce + "\n" + sha256Hex(body));
            var requestConfig = org.apache.http.client.config.RequestConfig.custom()
                    .setConnectTimeout(10000).setSocketTimeout(10000)
                    .setConnectionRequestTimeout(10000).setRedirectsEnabled(false).build();
            // JVM trust store supplies the mounted private CA; verification cannot be disabled.
            try (var client = org.apache.http.impl.client.HttpClients.custom()
                    .setDefaultRequestConfig(requestConfig).disableRedirectHandling()
                    .disableAutomaticRetries().build()) {
                var request = new org.apache.http.client.methods.HttpPost(destination);
                request.setHeader("Content-Type", "application/json");
                request.setHeader("X-Signature", signature);
                request.setHeader("X-Timestamp", timestamp);
                request.setHeader("X-Nonce", nonce);
                request.setEntity(new org.apache.http.entity.ByteArrayEntity(body));
                try (var response = client.execute(request)) {
                    if (response.getStatusLine().getStatusCode() != 200 || response.getEntity() == null) {
                        throw new IdentityBrokerException("Credential ingress rejected handoff");
                    }
                    try (var stream = response.getEntity().getContent()) {
                        byte[] reply = stream.readNBytes(65537);
                        if (reply.length > 65536) {
                            throw new IdentityBrokerException("Invalid credential ingress receipt");
                        }
                        JsonNode receipt = MAPPER.readTree(reply);
                        if (receipt == null || !expectedStatus.equals(receipt.path("status").asText())
                                || !payload.get("transaction_id").equals(receipt.path("transaction_id").asText())) {
                            throw new IdentityBrokerException("Invalid credential ingress receipt");
                        }
                    }
                }
            }
        } catch (IdentityBrokerException e) {
            throw e;
        } catch (Exception e) {
            throw new IdentityBrokerException("Credential ingress unavailable");
        }
    }

    private String getIssuerUrl(KeycloakSession session, RealmModel realm) {
        String frontendUrl = realm.getAttribute("frontendUrl");
        if (frontendUrl != null && !frontendUrl.isBlank()) {
            return frontendUrl.replaceAll("/+$", "") + "/realms/" + realm.getName();
        }
        return session.getContext().getUri().getBaseUri().toString().replaceAll("/+$", "") + "/realms/" + realm.getName();
    }

    public static String sha256Hex(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(data);
        return HexFormat.of().formatHex(hash);
    }

    public static String hmacSha256Hex(String secret, String data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(keySpec);
        byte[] rawHmac = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(rawHmac);
    }
}
