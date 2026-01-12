package com.sardes.springssecurityoauth2guidedtutorial

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.PropertySource
import org.springframework.http.HttpStatus
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository
import org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.security.web.authentication.HttpStatusEntryPoint
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter
import org.springframework.security.web.csrf.CookieCsrfTokenRepository
import org.springframework.security.web.csrf.CsrfToken
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.filter.OncePerRequestFilter
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.bodyToMono

@SpringBootApplication
@RestController
@PropertySource("file:secrets.properties")
class SpringsSecurityOauth2GuidedTutorialApplication {
    /**
     * This is the main application class for the Spring Security OAuth2 Guided Tutorial.
     * It demonstrates how to integrate OAuth2 login with Spring Security,
     * configure security rules, handle user information, and interact with external OAuth2 protected resources.
     *
     * The application uses Kotlin and Spring Boot to provide a hands-on learning experience for OAuth2.
     */
    /**
     * Handles requests to the "/user" endpoint.
     * This endpoint is secured and requires an authenticated user.
     *
     * @param principal The authenticated OAuth2User object, automatically injected by Spring Security.
     * @return A map containing the name of the authenticated user.
     */
    @GetMapping("/user")
    // The @AuthenticationPrincipal annotation is a Spring Security feature that allows
    // direct access to the authenticated principal (user) object.
    // In the context of OAuth2, this will be an OAuth2User object, which contains
    // details about the authenticated user from the OAuth2 provider.
    fun user(@AuthenticationPrincipal principal: OAuth2User): Map<String, Any?> {
        // Extracts the "name" attribute from the OAuth2User principal.
        // The attributes available depend on the OAuth2 provider (e.g., GitHub, Google).
        return mapOf("name" to principal.getAttribute("name"))
    }

    @GetMapping("/error")
    /**
     * Handles requests to the "/error" endpoint.
     * This endpoint is used to display error messages, typically after an authentication failure.
     *
     * @param request The HttpServletRequest object, used to retrieve session attributes.
     * @return The error message retrieved from the session, or null if no message is present.
     */
    // This endpoint is designed to display error messages, particularly after an OAuth2
    // authentication failure. The error message is stored in the HTTP session by the
    // custom authentication failure handler configured in `securityFilterChain`.
    // After displaying, the message is removed from the session to prevent it from persisting.
    fun error(request: HttpServletRequest): String? {
        val message = request.session.getAttribute("error.message") as String?
        request.session.removeAttribute("error.message")
        return message
    }

    private val failureHandler = SimpleUrlAuthenticationFailureHandler("/")
    // This is a standard Spring Security authentication failure handler.
    // It's configured to redirect to the root URL ("/") if an authentication attempt fails.
    // We use it here as a delegate within our custom OAuth2 authentication failure handler
    // to perform the redirection after we've stored the error message.

    /**
     * Configures the security filter chain for the application.
     * This is the core of Spring Security configuration, defining how requests are authorized,
     * authenticated, and handled for various security concerns.
     *
     * @param http The HttpSecurity object, used to configure web security.
     * @return A SecurityFilterChain instance.
     */
    @Bean
    // The @Bean annotation indicates that a method produces a bean to be managed by the Spring container.
    // Here, it's configuring the main security filter chain for the application.
    // The `HttpSecurity` object is a builder that allows configuring web-based security for specific http requests.
    // The `invoke` syntax is a Kotlin DSL (Domain Specific Language) feature for `HttpSecurity` that makes configuration more readable.
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http {
            // Configures authorization rules for different HTTP requests.
            authorizeHttpRequests {
                // Allows unauthenticated access to the root URL.
                authorize("/", permitAll)
                // Allows unauthenticated access to the "index.html" file.
                authorize("/index.html", permitAll)
                // Allows unauthenticated access to the "/error" endpoint.
                // This is crucial for displaying custom error pages (like the one defined by the `/error` endpoint)
                // without requiring authentication, especially after an authentication failure.
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
                // After logging out, the user will be redirected to the root URL.
                logoutSuccessUrl = "/"
                // `permitAll` ensures that the logout endpoint itself is accessible to all,
                // even unauthenticated users, which is necessary for a user to log out.
                permitAll
            }
            // Enables OAuth2 Login.
            // This automatically configures endpoints like /oauth2/authorization/{registrationId}
            // and handles the OAuth2 authorization code flow, redirecting users to the OAuth2 provider
            // for authentication and then back to the application.
            oauth2Login {
                // Configures a custom authentication failure handler for OAuth2 login.
                // This handler will be invoked if an OAuth2 authentication attempt fails (e.g., user denies access, invalid credentials).
                authenticationFailureHandler = AuthenticationFailureHandler { request, response, exception ->
                    // Stores the exception message in the session to be displayed on the "/error" page.
                    request.session.setAttribute("error.message", exception.message)

//                    SimpleUrlAuthenticationFailureHandler().onAuthenticationFailure(request, response, exception)
                    // Delegates to a SimpleUrlAuthenticationFailureHandler to redirect to the root URL ("/") after failure.
                    failureHandler.onAuthenticationFailure(request, response, exception)

                }
            }
            // Configures exception handling for security-related exceptions.
            exceptionHandling {
                // Sets an authentication entry point that returns an HTTP 401 Unauthorized status
                // when an unauthenticated user tries to access a protected resource.
                // This is particularly useful for REST APIs or single-page applications where
                // a redirect to a login page is not desired for unauthorized access.
                // Instead, a 401 status code is returned, which the client can then handle.
                authenticationEntryPoint = HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)
            }
            // Configures Cross-Site Request Forgery (CSRF) protection.
            // CSRF protection is vital for preventing malicious websites from tricking users
            // into performing unwanted actions on your application when they are authenticated.
            csrf {
                // Sets a CookieCsrfTokenRepository to store CSRF tokens in an HTTP-only cookie.
                // `withHttpOnlyFalse()` means the cookie is accessible by client-side JavaScript,
                // which is often needed for single-page applications (SPAs) to read the token
                // and include it in subsequent AJAX requests (e.g., in a header).
                csrfTokenRepository = CookieCsrfTokenRepository.withHttpOnlyFalse()
                // Sets a CsrfTokenRequestAttributeHandler to make the CSRF token available as a request attribute.
                // This allows the token to be accessed in views (e.g., Thymeleaf, JSP) using `_csrf`
                // or by other filters/components that need to retrieve the token from the request.
                csrfTokenRequestHandler = CsrfTokenRequestAttributeHandler()
            }

            // Adds a custom filter after the BasicAuthenticationFilter in the Spring Security filter chain.
            // This filter is responsible for ensuring the CSRF token is written to the cookie.
            addFilterAfter<BasicAuthenticationFilter>(object : OncePerRequestFilter() {
                override fun doFilterInternal(
                    request: HttpServletRequest,
                    response: HttpServletResponse,
                    filterChain: FilterChain,
                ) {
                    // Retrieves the CSRF token from the request attributes.
                    // The `CsrfTokenRequestAttributeHandler` (configured above) makes it available
                    // as a request attribute with the key `CsrfToken::class.java.name`.
                    val csrfToken = request.getAttribute(CsrfToken::class.java.name) as? CsrfToken

                    // actually saves the token into the cookie since it is deferred (lazy)
                    // In Spring Security 6 and later, the CSRF token is not automatically written to the cookie
                    // on every request by default. It's generated lazily.
                    // Accessing `csrfToken?.token` forces the token to be generated and
                    // written to the cookie by the `CsrfTokenRepository` (our `CookieCsrfTokenRepository`), if it hasn't been already.
                    // This is important for single-page applications that might make an initial
                    // GET request to get the CSRF token before subsequent POST requests.
                    csrfToken?.token
                    // Continues the filter chain.
                    filterChain.doFilter(request, response)
                }
            })
        }

        // Builds and returns the configured SecurityFilterChain.
        return http.build() // This finalizes the HttpSecurity configuration and creates the SecurityFilterChain bean.
    }

    /**
     * Configures a custom OAuth2UserService to enhance user information retrieval,
     * specifically for GitHub users to check organization membership.
     *
     * This bean overrides the default behavior of `DefaultOAuth2UserService` to:
     * 1. Load the basic OAuth2 user information.
     * 2. If the client registration is "github", it fetches the user's organizations
     *    using the provided `WebClient` and the user's access token.
     * 3. It then checks if the user is a member of the "spring-projects" organization.
     *    This is a specific business rule implemented for this tutorial to demonstrate
     *    how to enforce authorization based on external data obtained during OAuth2 login.
     * 4. If the user is not a member, it throws an `OAuth2AuthenticationException`,
     *    effectively preventing authentication.
     *
     * @param rest The `WebClient` instance configured for making HTTP requests,
     *             which includes OAuth2 authorized client capabilities.
     * @return An `OAuth2UserService` that can load and potentially enrich `OAuth2User` details.
     */
    @Bean
    // This bean customizes the OAuth2 user service. By default, Spring Security uses `DefaultOAuth2UserService`
    // to fetch user details from the OAuth2 provider's user info endpoint.
    // We are overriding this to add custom logic, specifically for GitHub users.
    fun oauth2UserService(rest: WebClient): OAuth2UserService<OAuth2UserRequest, OAuth2User> {
        // Create a default OAuth2UserService to handle the basic user information loading.
        // This delegate will perform the standard steps of fetching user attributes from the OAuth2 provider.
        val delegate = DefaultOAuth2UserService()

        return OAuth2UserService { request ->
            // Load the basic OAuth2User information using the delegate service.
            val user = delegate.loadUser(request)

            if (request.clientRegistration.registrationId != "github") {
                return@OAuth2UserService user
            }

            val client = OAuth2AuthorizedClient(
                request.clientRegistration,
                user.name,
                request.accessToken
            )

            // Get the URL for fetching user organizations from the OAuth2User attributes.
            // GitHub's user info endpoint typically provides this URL.
            val url = user.getAttribute<String>("organizations_url") ?: ""

            // Use the WebClient to fetch the user's organizations.
            // The `oauth2AuthorizedClient` attribute (provided by `ServletOAuth2AuthorizedClientExchangeFilterFunction`
            // in the `rest` WebClient bean) ensures that the user's access token is automatically
            // included in the Authorization header of this request to GitHub's API.
            val orgs = rest.get()
                .uri(url)
                .attributes(oauth2AuthorizedClient(client))
                .retrieve()
                .bodyToMono<List<Map<String, Any>>>()
                .block() // `block()` is used here for simplicity in a synchronous context. In a reactive application, you'd typically use `subscribe()`.

            val isMember = orgs?.any {
                it["login"] == "spring-projects"
                // The "login" attribute typically holds the organization's name or identifier.
            } ?: false

            if (!isMember) {
                 throw OAuth2AuthenticationException(
                    OAuth2Error("invalid_token", "Not in Spring Team. You have to be member first.", "")
                 )
            }

            // If all checks pass, return the original OAuth2User.
            user
        }
    }

    @Bean
    /**
     * Configures and provides a `WebClient` bean that is capable of automatically
     * including OAuth2 access tokens in its requests.
     *
     * This `WebClient` is essential for making authenticated calls to external
     * OAuth2 protected resources (like GitHub's API) on behalf of the currently
     * authenticated user.
     *
     * @param clients The `ClientRegistrationRepository` to retrieve client registration details.
     * @param authz The `OAuth2AuthorizedClientRepository` to store and retrieve authorized clients.
     * @return A `WebClient` instance pre-configured with OAuth2 authorization capabilities.
     */
    fun rest(clients: ClientRegistrationRepository, authz: OAuth2AuthorizedClientRepository): WebClient {
        // Create a `ServletOAuth2AuthorizedClientExchangeFilterFunction`.
        // This is a crucial component for making authenticated HTTP requests to OAuth2 protected resources.
        // It acts as a `ClientRequestFilter` for `WebClient` that automatically:
        // 1. Looks up an `OAuth2AuthorizedClient` for the current user and target OAuth2 client registration.
        // 2. If found, it adds the access token to the `Authorization` header of the outgoing request.
        // 3. It can also refresh tokens if they are expired.
        val oauth2 = ServletOAuth2AuthorizedClientExchangeFilterFunction(clients, authz)

        // Build the WebClient, applying the OAuth2 filter.
        // Any request made with this `WebClient` instance will automatically attempt to include an OAuth2 access token.
        return WebClient.builder()
            .filter(oauth2)
            .build()

    }

}

fun main(args: Array<String>) {
    runApplication<SpringsSecurityOauth2GuidedTutorialApplication>(*args)
}
