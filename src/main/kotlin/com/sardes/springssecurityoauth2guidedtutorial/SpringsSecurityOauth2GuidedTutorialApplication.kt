package com.sardes.springssecurityoauth2guidedtutorial

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpStatus
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.HttpStatusEntryPoint
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@SpringBootApplication
@RestController
class SpringsSecurityOauth2GuidedTutorialApplication {

    @GetMapping("/user")
    fun user(@AuthenticationPrincipal principal: OAuth2User): Map<String, Any?> {
        return mapOf("name" to principal.getAttribute("name"))
    }

    // VERY VERY OLD WAY TO DO THE SAME THING AS `securityFilterChain`
//    fun configure(http: HttpSecurity) {
//        http
//            .authorizeHttpRequests { a -> a
//                .requestMatchers("/", "/error", "/webjars/**")
//                .permitAll()
//                .anyRequest().authenticated()
//            }
//            .exceptionHandling { e -> e
//                .authenticationEntryPoint(HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
//            }
//            .oauth2Login{}
//    }

    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http {
            authorizeHttpRequests {
                authorize("/", permitAll)
                authorize("/index.html", permitAll)
                authorize("/error", permitAll)
                authorize("/webjars/**", permitAll)
                authorize(anyRequest, authenticated)
            }
            logout {
                logoutSuccessUrl = "/"
                permitAll
            }
            oauth2Login {  }
            exceptionHandling {
                authenticationEntryPoint = HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)
            }
        }

        return http.build()
    }

}

fun main(args: Array<String>) {
    runApplication<SpringsSecurityOauth2GuidedTutorialApplication>(*args)
}
