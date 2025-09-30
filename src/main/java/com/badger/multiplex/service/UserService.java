package com.badger.multiplex.service;

import com.badger.multiplex.dto.UserDto;
// Import your actual JPA entities and repository
import com.badger.multiplex.user.User;
import com.badger.multiplex.user.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * Service layer responsible for fetching complete user details from the database
 * and converting the JPA Entity into a DTO for API consumption.
 */
@Service
public class UserService {

    // 1. DEPENDENCY: Use (depend on) the Repository, don't implement it.
    private final UserRepository userRepository;

    @Autowired
    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * Finds the full user profile by the provider ID (which is the 'id' in the JWT).
     * Converts the database Entity into the API DTO.
     * @param providerId The user's provider ID/email extracted from the JWT.
     * @return An Optional containing the UserDto if found.
     */
    public Optional<UserDto> findByProviderId(String providerId) {

        // 2. Fetch the JPA Entity from the database
        Optional<User> userEntityOpt = userRepository.findByProviderId(providerId);

        // 3. Convert the Entity to the DTO
        return userEntityOpt.map(userEntity -> {
            // Mapping logic here
            return new UserDto(
                userEntity.getProviderId(), // Assumes the User entity has this method
                userEntity.getName(),       // Assumes the User entity has this method
                userEntity.getEmail()       // Assumes the User entity has this method
            );
        });
    }
}
