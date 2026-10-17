package com.burp2api.services;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.InteractionFilter;
import burp.api.montoya.collaborator.PayloadOption;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * Maintains a single, extension-lived Burp Collaborator client so that payloads
 * minted through the API can be polled back through the API.
 *
 * <p>Burp's default payload generator routes interactions to the Collaborator
 * tab only; those payloads have no client that the API can poll. By generating
 * every API payload from one persistent client, callers can confirm blind/OOB
 * findings end-to-end with {@code GET /collaborator/interactions?payload=...}
 * without juggling a client secret.
 *
 * <p>The client secret is sensitive material and is never logged or persisted to
 * disk; the client lives for as long as the extension is loaded.
 */
public class CollaboratorService {
    private static final Logger logger = LoggerFactory.getLogger(CollaboratorService.class);

    private final MontoyaApi api;
    private volatile CollaboratorClient client;

    public CollaboratorService(MontoyaApi api) {
        this.api = api;
    }

    /**
     * Returns the shared API Collaborator client, creating it on first use.
     * Throws {@link IllegalStateException} if Collaborator is disabled.
     */
    public synchronized CollaboratorClient client() {
        if (client == null) {
            client = api.collaborator().createClient();
            logger.info("Created persistent API Collaborator client for pollable payloads");
        }
        return client;
    }

    /** Whether the shared client has been created yet. */
    public boolean hasClient() {
        return client != null;
    }

    /**
     * Generates a payload from the shared client.
     * @param customData optional correlation tag embedded in the payload, or null
     * @param options    payload generation options
     */
    public CollaboratorPayload generatePayload(String customData, PayloadOption... options) {
        CollaboratorClient c = client();
        if (customData != null && !customData.isEmpty()) {
            return c.generatePayload(customData, options);
        }
        return c.generatePayload(options);
    }

    /** Interactions recorded for a specific payload string (full Collaborator hostname). */
    public List<Interaction> interactionsByPayload(String payload) {
        return client().getInteractions(InteractionFilter.interactionPayloadFilter(payload));
    }

    /** Interactions recorded for a specific interaction id. */
    public List<Interaction> interactionsById(String interactionId) {
        return client().getInteractions(InteractionFilter.interactionIdFilter(interactionId));
    }

    /** All interactions recorded for the shared client since the last poll. */
    public List<Interaction> allInteractions() {
        return client().getAllInteractions();
    }
}
