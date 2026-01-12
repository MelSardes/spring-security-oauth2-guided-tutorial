package com.sardes.springssecurityoauth2guidedtutorial

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Bean
import org.springframework.http.HttpStatus
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.HttpStatusEntryPoint
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter
import org.springframework.security.web.csrf.CookieCsrfTokenRepository
import org.springframework.security.web.csrf.CsrfToken
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler
import org.springframework.security.web.util.matcher.RequestMatcherEntry
import org.springframework.security.web.util.matcher.RequestMatchers
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.filter.OncePerRequestFilter

@SpringBootApplication
@RestController
class SpringsSecurityOauth2GuidedTutorialApplication {
    /**
     * Handles requests to the "/user" endpoint.
     * This endpoint is secured and requires an authenticated user.
     *
     * @param principal The authenticated OAuth2User object, automatically injected by Spring Security.
     * @return A map containing the name of the authenticated user.
     */
    @GetMapping("/user")
    fun user(@AuthenticationPrincipal principal: OAuth2User): Map<String, Any?> {
        // Extracts the "name" attribute from the OAuth2User principal.
        // The attributes available depend on the OAuth2 provider (e.g., GitHub, Google).
        return mapOf("name" to principal.getAttribute("name"))
    }

    /**
     * Configures the security filter chain for the application.
     * This is the core of Spring Security configuration, defining how requests are authorized,
     * authenticated, and handled for various security concerns.
     *
     * @param http The HttpSecurity object, used to configure web security.
     * @return A SecurityFilterChain instance.
     */
    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http {
            // Configures authorization rules for different HTTP requests.
            authorizeHttpRequests {
                // Allows unauthenticated access to the root URL.
                authorize("/", permitAll)
                // Allows unauthenticated access to the "index.html" file.
                authorize("/index.html", permitAll)
                // Allows unauthenticated access to the "/error" endpoint.
                // This is useful for displaying custom error pages without requiring authentication.
                authorize("/error", permitAll)
                // Allows unauthenticated access to resources under "/webjars/**".
                // WebJars are client-side web libraries (like Bootstrap, jQuery) packaged as JARs.
                authorize("/webjars/**", permitAll)
                // Requires authentication for any other request not explicitly permitted above.
                // This means users must be logged in to access most parts of the application.
                authorize(anyRequest, authenticated)
            }
            // Configures logout functionality.
            logout {
                // Specifies the URL to redirect to after a successful logout.
                logoutSuccessUrl = "/"
                permitAll
            }
            // Enables OAuth2 Login.
            // This automatically configures endpoints like /oauth2/authorization/{registrationId}
            // and handles the OAuth2 authorization code flow.
            oauth2Login {  }
            // Configures exception handling for security-related exceptions.
            exceptionHandling {
                // Sets an authentication entry point that returns an HTTP 401 Unauthorized status
                // when an unauthenticated user tries to access a protected resource.
                // This is common for REST APIs or single-page applications.
                authenticationEntryPoint = HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)
            }
            // Configures Cross-Site Request Forgery (CSRF) protection.
            csrf {
                // Sets a CookieCsrfTokenRepository to store CSRF tokens in an HTTP-only cookie.
                // `withHttpOnlyFalse()` means the cookie is accessible by client-side JavaScript,
                // which is often needed for single-page applications to read the token and include it in requests.
                csrfTokenRepository = CookieCsrfTokenRepository.withHttpOnlyFalse()
                // Sets a CsrfTokenRequestAttributeHandler to make the CSRF token available as a request attribute.
                // This allows the token to be accessed in views or by other filters.
                csrfTokenRequestHandler = CsrfTokenRequestAttributeHandler()
            }

            // Adds a custom filter after the BasicAuthenticationFilter in the Spring Security filter chain.
            // This filter is responsible for ensuring the CSRF token is written to the cookie.
            addFilterAfter<BasicAuthenticationFilter>(object : OncePerRequestFilter() {
                override fun doFilterInternal(
                    request: HttpServletRequest,
                    response: HttpServletResponse,
                    filterChain: FilterChain
                ) {
                    // Retrieves the CSRF token from the request attributes.
                    // The CsrfTokenRequestAttributeHandler makes it available under this name.
                    val csrfToken = request.getAttribute(CsrfToken::class.java.name) as? CsrfToken

                    // actually saves the token into the cookie since it is deferred (lazy)
                    // It won't be written by default since SS7
                    // Accessing `csrfToken?.token` forces the token to be generated and
                    // written to the cookie by the CsrfTokenRepository, if it hasn't been already.
                    // This is important for single-page applications that might make an initial
                    // GET request to get the CSRF token before subsequent POST requests.
                    csrfToken?.token
                    // Continues the filter chain.
                    filterChain.doFilter(request, response)
                }
            })
        }

        // Builds and returns the configured SecurityFilterChain.
        return http.build()
    }

}

fun main(args: Array<String>) {
    runApplication<SpringsSecurityOauth2GuidedTutorialApplication>(*args)
}
