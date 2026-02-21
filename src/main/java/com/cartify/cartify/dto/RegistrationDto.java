package com.cartify.cartify.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * DTO (Data Transfer Object) for user registration form.
 *
 * Carries the raw data submitted by the user from the registration page.
 * Validated with Bean Validation annotations before reaching the service layer.
 * Passwords are NEVER stored here after processing — only the encoded hash goes to the DB.
 */
public class RegistrationDto {

    // -------------------------------------------------------------------------
    // Full Name
    // -------------------------------------------------------------------------

    /** Customer's full name — required, bounded length. */
    @NotBlank(message = "Full name is required")
    @Size(min = 2, max = 100, message = "Full name must be between 2 and 100 characters")
    private String fullName;

    // -------------------------------------------------------------------------
    // Email
    // -------------------------------------------------------------------------

    /** Must be a valid email format and will be checked for uniqueness in the service layer. */
    @NotBlank(message = "Email is required")
    @Email(message = "Please enter a valid email address")
    private String email;

    // -------------------------------------------------------------------------
    // Password — strong password policy enforced via regex
    // -------------------------------------------------------------------------

    /**
     * Raw plain-text password submitted by the user.
     * Rules (enforced by regex):
     *   - At least 8 characters
     *   - At least 1 uppercase letter (A-Z)
     *   - At least 1 lowercase letter (a-z)
     *   - At least 1 digit (0-9)
     *   - At least 1 special character (!@#$%^&*...)
     *
     * This field is NEVER persisted.  It is encoded by BCrypt in the service layer.
     */
    @NotBlank(message = "Password is required")
    @Pattern(
        regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>\\/?]).{8,}$",
        message = "Password must be at least 8 characters and include uppercase, lowercase, number, and special character"
    )
    private String password;

    // -------------------------------------------------------------------------
    // Confirm Password — cross-field match is validated in the controller
    // -------------------------------------------------------------------------

    /** Must equal {@code password}.  Match is checked in AuthController via BindingResult. */
    @NotBlank(message = "Please confirm your password")
    private String confirmPassword;

    // -------------------------------------------------------------------------
    // Phone Number (optional)
    // -------------------------------------------------------------------------

    /** Optional phone number — validated only when provided. */
    @Pattern(
        regexp = "^$|^[+]?[(]?[0-9]{1,4}[)]?[-\\s./0-9]{6,14}$",
        message = "Please enter a valid phone number"
    )
    private String phoneNumber;

    // -------------------------------------------------------------------------
    // Getters & Setters (no Lombok to keep DTO explicit and framework-agnostic)
    // -------------------------------------------------------------------------

    public String getFullName() { return fullName; }
    public void setFullName(String fullName) { this.fullName = fullName; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }

    public String getConfirmPassword() { return confirmPassword; }
    public void setConfirmPassword(String confirmPassword) { this.confirmPassword = confirmPassword; }

    public String getPhoneNumber() { return phoneNumber; }
    public void setPhoneNumber(String phoneNumber) { this.phoneNumber = phoneNumber; }
}
