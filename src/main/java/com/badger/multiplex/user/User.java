package com.badger.multiplex.user;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "users") // Renamed to avoid reserved keyword 'user' in some databases
@Getter
@Setter
@NoArgsConstructor
public class User {

    // The unique ID from the OAuth2 provider (e.g., Google's sub value)
    @Id
    private String providerId;

    // The name of the OAuth2 provider (e.g., "google")
    private String provider;

    private String name;

    private String email;

    public User(String providerId, String provider, String name, String email) {
        this.providerId = providerId;
        this.provider = provider;
        this.name = name;
        this.email = email;
    }
}
