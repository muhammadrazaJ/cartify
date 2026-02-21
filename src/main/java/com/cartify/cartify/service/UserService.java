package com.cartify.cartify.service;

import com.cartify.cartify.dto.RegistrationDto;

/**
 * Service interface for user-related business operations.
 *
 * Follows the Interface-Impl pattern so that the controller depends on an
 * abstraction rather than a concrete class, making it easy to swap
 * implementations (e.g. for testing) without touching the controller.
 */
public interface UserService {

    /**
     * Registers a new customer account.
     *
     * <p>Responsibilities:
     * <ol>
     *   <li>Verify that the email is not already in use.</li>
     *   <li>Encode the plain-text password with BCrypt.</li>
     *   <li>Persist the new {@link com.cartify.cartify.entity.User} with role CUSTOMER
     *       and status ACTIVE.</li>
     * </ol>
     *
     * @param dto the validated registration form data
     * @throws IllegalArgumentException if the email address is already registered
     */
    void registerCustomer(RegistrationDto dto);

    /**
     * Checks whether a given email address is already associated with an account.
     *
     * @param email the email to query
     * @return {@code true} if the email already exists in the database
     */
    boolean emailExists(String email);
}
