package com.cartify.cartify.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Custom authentication success handler for Cartify.
 *
 * <p>After a successful login it inspects the user's granted authority and
 * redirects accordingly:
 * <ul>
 *   <li>ROLE_ADMIN    → /admin/dashboard</li>
 *   <li>ROLE_CUSTOMER → /home (default)</li>
 * </ul>
 *
 * <p>If Spring Security saved a protected URL the user tried to reach before
 * being redirected to login, that saved request is honoured first (standard
 * Spring Security behaviour). This prevents open-redirect attacks because the
 * saved URL is always relative to the application context.
 */
@Component
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    /**
     * Used to retrieve any URL the user was trying to access before being
     * redirected to the login page. We clear it after use so it cannot be
     * replayed.
     */
    private final RequestCache requestCache = new HttpSessionRequestCache();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        // ---- 1. Check for a saved protected URL (e.g. user tried /orders/1 before login) ----
        SavedRequest savedRequest = requestCache.getRequest(request, response);
        if (savedRequest != null) {
            // Clear it so it can't be reused / replayed
            requestCache.removeRequest(request, response);
            String targetUrl = savedRequest.getRedirectUrl();
            response.sendRedirect(targetUrl);
            return;
        }

        // ---- 2. Role-based default redirect ----
        String redirectUrl = determineTargetUrl(authentication);
        response.sendRedirect(request.getContextPath() + redirectUrl);
    }

    /**
     * Determines the redirect URL based on the user's single role.
     * Falls back to "/home" for any unknown authority.
     */
    private String determineTargetUrl(Authentication authentication) {
        for (GrantedAuthority authority : authentication.getAuthorities()) {
            if ("ROLE_ADMIN".equals(authority.getAuthority())) {
                return "/admin/dashboard";
            }
        }
        // Default: CUSTOMER or any other role goes to home
        return "/home";
    }
}
