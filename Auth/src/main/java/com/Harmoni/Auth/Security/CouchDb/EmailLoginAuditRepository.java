package com.Harmoni.Auth.Security.CouchDb;

import org.lightcouch.CouchDbClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.UUID;

@Repository
public class EmailLoginAuditRepository {

    @Autowired
    private CouchDbClient couchDbClient;

    public void save(EmailLoginAudit audit) {
        if (audit.getId() == null) {
            audit.setId(UUID.randomUUID().toString());
        }
        if (audit.getTimestamp() == null) {
            audit.setTimestamp(Instant.now().toString());
        }
        try {
            couchDbClient.save(audit);
        } catch (Exception e) {
            System.err.println("CouchDB audit save failed: " + e.getMessage());
        }
    }

    public void logEvent(String email, String type, String status, String userId, String message) {
        EmailLoginAudit audit = EmailLoginAudit.builder()
                .id(UUID.randomUUID().toString())
                .email(email)
                .type(type)
                .status(status)
                .timestamp(Instant.now().toString())
                .userId(userId)
                .message(message)
                .build();
        save(audit);
    }
}
