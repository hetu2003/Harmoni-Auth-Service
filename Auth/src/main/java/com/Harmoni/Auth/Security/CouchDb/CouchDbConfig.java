package com.Harmoni.Auth.Security.CouchDb;

import org.lightcouch.CouchDbClient;
import org.lightcouch.CouchDbProperties;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class CouchDbConfig {

    @Value("${couchdb.host}")
    private String host;

    @Value("${couchdb.port}")
    private int port;

    @Value("${couchdb.username}")
    private String username;

    @Value("${couchdb.password}")
    private String password;

    @Value("${couchdb.database}")
    private String database;

    @Bean
    public CouchDbClient couchDbClient() {
        CouchDbProperties properties = new CouchDbProperties()
                .setDbName(database)
                .setCreateDbIfNotExist(true)
                .setProtocol("http")
                .setHost(host)
                .setPort(port)
                .setUsername(username)
                .setPassword(password)
                .setMaxConnections(10)
                .setConnectionTimeout(0);
        return new CouchDbClient(properties);
    }
}
