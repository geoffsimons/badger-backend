package com.badger.multiplex.user;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "users") // Renamed to avoid reserved keyword 'user' in some databases
public class User {

    // The unique ID from the OAuth2 provider (e.g., Google's sub value)
    @Id
    private String providerId;

    // The name of the OAuth2 provider (e.g., "google")
    private String provider;

    private String name;

    private String email;

    public User() {
    }

    // All-args constructor
    public User(String providerId, String provider, String name, String email) {
        this.providerId = providerId;
        this.provider = provider;
        this.name = name;
        this.email = email;
    }

    // Explicit Getters and Setters (replaces @Getter and @Setter)

    public String getProviderId() {
        return providerId;
    }

    public void setProviderId(String providerId) {
        this.providerId = providerId;
    }

    public String getProvider() {
        return provider;
    }

    public void setProvider(String provider) {
        this.provider = provider;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }
}
