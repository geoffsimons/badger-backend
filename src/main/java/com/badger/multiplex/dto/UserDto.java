package com.badger.multiplex.dto;

/**
 * Data Transfer Object (DTO) representing the user profile details fetched from the database.
 * In a real application, this might map directly to a JPA Entity.
 */
public class UserDto {
    private String id;
    private String name;
    private String email;

    public UserDto(String id, String name, String email) {
        this.id = id;
        this.name = name;
        this.email = email;
    }

    // Getters and Setters (omitted for brevity in this response, but required in production)

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
}
