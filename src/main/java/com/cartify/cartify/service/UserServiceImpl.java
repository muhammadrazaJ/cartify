package com.cartify.cartify.service;

import com.cartify.cartify.dto.RegistrationDto;
import com.cartify.cartify.entity.Role;
import com.cartify.cartify.entity.User;
import com.cartify.cartify.entity.UserStatus;
import com.cartify.cartify.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Concrete implementation of {@link UserService}.
 *
 * Handles all user-related business logic:
 *   - Unique email enforcement
 *   - BCrypt password encoding (delegated to Spring Security's PasswordEncoder bean)
 *   - Persisting the new User entity via JPA
 *
 * Annotated with @Service so Spring picks it up for component scanning.
 * The @Transactional annotation ensures that DB writes are committed atomically.
 */
@Service
@Transactional
public class UserServiceImpl implements UserService {

    // -------------------------------------------------------------------------
    // Dependencies
    // -------------------------------------------------------------------------

    /** JPA repository for CRUD operations on the User table. */
    private final UserRepository userRepository;

    /**
     * BCrypt encoder injected from {@link com.cartify.cartify.config.SecurityConfig}.
     * Using the bean (not a new instance) ensures the same strength setting is used everywhere.
     */
    private final PasswordEncoder passwordEncoder;

    // -------------------------------------------------------------------------
    // Constructor injection (preferred over @Autowired field injection)
    // -------------------------------------------------------------------------

    public UserServiceImpl(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    // -------------------------------------------------------------------------
    // UserService implementation
    // -------------------------------------------------------------------------

    /**
     * Registers a new CUSTOMER account.
     *
     * Steps:
     * 1. Guard: check email uniqueness.
     * 2. Build a new User entity from the DTO fields.
     * 3. Encode the plain-text password with BCrypt — never store raw passwords.
     * 4. Assign default role (CUSTOMER) and status (ACTIVE).
     * 5. Persist via UserRepository.
     *
     * @param dto validated registration form data
     * @throws IllegalArgumentException when the email is already taken
     */
    @Override
    public void registerCustomer(RegistrationDto dto) {
        // Step 1 — Uniqueness guard (defensive; the controller also checks via emailExists())
        if (userRepository.existsByEmail(dto.getEmail())) {
            throw new IllegalArgumentException("An account with email '" + dto.getEmail() + "' already exists.");
        }

        // Step 2 — Build entity
        User user = new User();
        user.setFullName(dto.getFullName().trim());
        user.setEmail(dto.getEmail().trim().toLowerCase()); // normalise email to lower-case

        // Step 3 — Encode password with BCrypt BEFORE persisting
        user.setPasswordHash(passwordEncoder.encode(dto.getPassword()));

        // Step 4 — Set defaults
        user.setRole(Role.CUSTOMER);
        user.setStatus(UserStatus.ACTIVE);

        // Phone number is optional — only set if provided
        if (dto.getPhoneNumber() != null && !dto.getPhoneNumber().isBlank()) {
            user.setPhoneNumber(dto.getPhoneNumber().trim());
        }

        // Step 5 — Persist
        userRepository.save(user);
    }

    /**
     * Delegates to the repository to check email uniqueness.
     * Called by the controller before service-layer registration to give
     * a user-friendly BindingResult error rather than a generic exception.
     *
     * @param email email to check
     * @return true if the email is already registered
     */
    @Override
    @Transactional(readOnly = true)
    public boolean emailExists(String email) {
        return userRepository.existsByEmail(email != null ? email.trim().toLowerCase() : "");
    }
}
