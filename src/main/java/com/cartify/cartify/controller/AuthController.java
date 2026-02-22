package com.cartify.cartify.controller;

import com.cartify.cartify.dto.RegistrationDto;
import com.cartify.cartify.service.UserService;
import jakarta.validation.Valid;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

/**
 * Controller responsible for authentication-related routes:
 *   GET  /register  — display the registration form
 *   POST /register  — process form submission
 *   GET  /login     — display the login page (Spring Security renders it)
 *
 * Follows the thin-controller pattern: validation is declared via Bean Validation
 * annotations on the DTO; business logic lives in UserService.
 */
@Controller
public class AuthController {

    // -------------------------------------------------------------------------
    // Dependencies
    // -------------------------------------------------------------------------

    /** Business-logic layer for user operations (register, email-check, etc.). */
    private final UserService userService;

    public AuthController(UserService userService) {
        this.userService = userService;
    }

    // -------------------------------------------------------------------------
    // Registration — GET
    // -------------------------------------------------------------------------

    /**
     * Displays the registration form with an empty {@link RegistrationDto} bound
     * to the Thymeleaf form so that th:field bindings work correctly.
     *
     * @param model Spring MVC model to pass data to the view
     * @return name of the Thymeleaf template to render (registration.html)
     */
    @GetMapping("/register")
    public String showRegistrationForm(Model model) {
        model.addAttribute("registerDto", new RegistrationDto()); // was "registrationDto"
        return "registration";
    }

    // -------------------------------------------------------------------------
    // Registration — POST
    // -------------------------------------------------------------------------

    /**
     * Processes the submitted registration form.
     *
     * Flow:
     * 1. @Valid triggers Bean Validation on the DTO.
     * 2. BindingResult captures any constraint violations.
     * 3. Custom cross-field checks (confirm password, email uniqueness) are added
     *    to BindingResult manually.
     * 4. If any errors exist → re-render the form with error messages.
     * 5. If all checks pass → delegate to UserService, then redirect to login.
     *
     * @param dto           the form data bound from the HTTP POST request
     * @param bindingResult carries Bean Validation errors (must immediately follow @ModelAttribute)
     * @param model         Spring MVC model for passing data back to the view on error
     * @return redirect to /login?registered on success, or the form view on failure
     */
    @PostMapping("/register")
    public String processRegistration(
            @Valid @ModelAttribute("registerDto") RegistrationDto dto, // was "registrationDto"
            BindingResult bindingResult,
            Model model
    ) {
        // ------------------------------------------------------------------
        // Step 1 — Cross-field validation: confirm password must match password
        // ------------------------------------------------------------------
        if (!dto.getPassword().equals(dto.getConfirmPassword())) {
            bindingResult.rejectValue(
                "confirmPassword",          // field name in the DTO
                "error.confirmPassword",    // error code (for i18n key lookup)
                "Passwords do not match"    // default message
            );
        }

        // ------------------------------------------------------------------
        // Step 2 — Business validation: email must be unique
        // Checked here (not only in the service) so we can surface a clean
        // BindingResult field error rather than catching an exception.
        // ------------------------------------------------------------------
        if (!bindingResult.hasFieldErrors("email") && userService.emailExists(dto.getEmail())) {
            bindingResult.rejectValue(
                "email",
                "error.email.exists",
                "An account with this email already exists"
            );
        }

        // ------------------------------------------------------------------
        // Step 3 — If any validation errors exist, redisplay the form
        // ------------------------------------------------------------------
        if (bindingResult.hasErrors()) {
            // model already has "registrationDto" from @ModelAttribute binding
            return "registration";
        }

        // ------------------------------------------------------------------
        // Step 4 — All validations passed; delegate registration to service
        // ------------------------------------------------------------------
        userService.registerCustomer(dto);

        // ------------------------------------------------------------------
        // Step 5 — Redirect to login page with a ?registered query parameter
        //          that the login template uses to show a success banner.
        // ------------------------------------------------------------------
        return "redirect:/login?registered";
    }

    // -------------------------------------------------------------------------
    // Login — GET
    // -------------------------------------------------------------------------

    /**
     * Renders the login page.
     * Spring Security handles the POST /login form submission automatically;
     * we only need to serve the GET so we can use a custom Thymeleaf template.
     *
     * @return name of the Thymeleaf template (login.html)
     */
    @GetMapping("/login")
    public String showLoginPage() {
        return "login"; // resolves to templates/login.html
    }
}
