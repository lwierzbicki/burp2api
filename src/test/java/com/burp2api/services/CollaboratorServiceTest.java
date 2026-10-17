package com.burp2api.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.Collaborator;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.InteractionFilter;
import burp.api.montoya.collaborator.PayloadOption;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

class CollaboratorServiceTest {

    private MontoyaApi api;
    private Collaborator collaborator;
    private CollaboratorClient client;
    private CollaboratorService service;

    @BeforeEach
    void setUp() {
        api = mock(MontoyaApi.class);
        collaborator = mock(Collaborator.class);
        client = mock(CollaboratorClient.class);
        when(api.collaborator()).thenReturn(collaborator);
        when(collaborator.createClient()).thenReturn(client);
        service = new CollaboratorService(api);
    }

    @Test
    void reusesASingleClientAcrossCalls() {
        CollaboratorClient first = service.client();
        CollaboratorClient second = service.client();

        assertThat(first).isSameAs(second);
        verify(collaborator, times(1)).createClient();
    }

    @Test
    void generatePayloadWithoutCustomDataDelegatesToClient() {
        CollaboratorPayload payload = mock(CollaboratorPayload.class);
        when(client.generatePayload(any(PayloadOption[].class))).thenReturn(payload);

        CollaboratorPayload result = service.generatePayload(null);

        assertThat(result).isSameAs(payload);
        verify(client).generatePayload(any(PayloadOption[].class));
    }

    @Test
    void generatePayloadWithCustomDataUsesCustomDataOverload() {
        CollaboratorPayload payload = mock(CollaboratorPayload.class);
        when(client.generatePayload(eq("probe-7"), any(PayloadOption[].class))).thenReturn(payload);

        CollaboratorPayload result = service.generatePayload("probe-7");

        assertThat(result).isSameAs(payload);
        verify(client).generatePayload(eq("probe-7"), any(PayloadOption[].class));
    }

    @Test
    void interactionsByPayloadFiltersTheClient() {
        @SuppressWarnings("unchecked")
        List<Interaction> expected = mock(List.class);
        InteractionFilter filter = mock(InteractionFilter.class);
        when(client.getInteractions(filter)).thenReturn(expected);

        try (MockedStatic<InteractionFilter> filters = mockStatic(InteractionFilter.class)) {
            filters.when(() -> InteractionFilter.interactionPayloadFilter("abc123.oastify.com"))
                .thenReturn(filter);

            List<Interaction> result = service.interactionsByPayload("abc123.oastify.com");

            assertThat(result).isSameAs(expected);
            verify(client).getInteractions(filter);
        }
    }

    @Test
    void interactionsByIdFiltersTheClient() {
        @SuppressWarnings("unchecked")
        List<Interaction> expected = mock(List.class);
        InteractionFilter filter = mock(InteractionFilter.class);
        when(client.getInteractions(filter)).thenReturn(expected);

        try (MockedStatic<InteractionFilter> filters = mockStatic(InteractionFilter.class)) {
            filters.when(() -> InteractionFilter.interactionIdFilter("abc123"))
                .thenReturn(filter);

            List<Interaction> result = service.interactionsById("abc123");

            assertThat(result).isSameAs(expected);
            verify(client).getInteractions(filter);
        }
    }

    @Test
    void allInteractionsReturnsEverythingForTheClient() {
        @SuppressWarnings("unchecked")
        List<Interaction> expected = mock(List.class);
        when(client.getAllInteractions()).thenReturn(expected);

        List<Interaction> result = service.allInteractions();

        assertThat(result).isSameAs(expected);
        verify(client).getAllInteractions();
    }

    @Test
    void hasClientReflectsLazyCreation() {
        assertThat(service.hasClient()).isFalse();
        service.client();
        assertThat(service.hasClient()).isTrue();
    }
}
