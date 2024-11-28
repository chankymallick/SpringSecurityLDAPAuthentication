package com.quest.questdemo.config;

import com.quest.questdemo.config.authproviders.CustomDBAuthenticationProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.authentication.LdapAuthenticator;
import org.springframework.security.ldap.server.UnboundIdContainer;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

//    @Autowired
//    DataSource dataSource;
//  
//    @Autowired
//    private CustomDBAuthenticationProvider customDBAuthenticationProvider;
//    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorizeRequests -> authorizeRequests
                .requestMatchers("/LoginPage", "/WEB-INF/views/**").permitAll()
                .anyRequest().authenticated()
                )
                .formLogin(formLogin -> formLogin
                .loginPage("/LoginPage")
                .loginProcessingUrl("/login")
                .defaultSuccessUrl("/home", true)
                .permitAll()
                )
                .logout(logout -> logout
                .logoutSuccessUrl("/LoginPage")
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .permitAll()
                )
                .csrf().disable();
        return http.build();
    }

    // UserDetailsService interface is Customizable , we can implement loadUserByusername where as JdbcUserDetailsManager is more of a
    // concrete ready to use class with user & roles creation / update / delete features with query available.    
//    @Bean
//    public UserDetailsService userDetailsService() {
//        JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
//        jdbcUserDetailsManager.setUsersByUsernameQuery("SELECT username, password, enabled FROM users WHERE username = ?");
//        jdbcUserDetailsManager.setAuthoritiesByUsernameQuery("SELECT username, authority FROM authorities WHERE username = ?");
//        return jdbcUserDetailsManager;
//    }    
//    @Bean
//    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
//        AuthenticationManagerBuilder authenticationManagerBuilder
//                = http.getSharedObject(AuthenticationManagerBuilder.class);
//        authenticationManagerBuilder.authenticationProvider(customDBAuthenticationProvider);
//        return authenticationManagerBuilder.build();
//    }
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

//    @Bean
//    public CustomDBAuthenticationProvider customAuthenticationProvider() {
//        return new CustomDBAuthenticationProvider();
//    }
    @Bean
    public UnboundIdContainer ldapContainer() {
        UnboundIdContainer container = new UnboundIdContainer("dc=springframework,dc=org", "classpath:users.ldif");
        container.setPort(8389); // Ensure this port is not already in use
        return container;
    }

    @Bean
    DefaultSpringSecurityContextSource contextSource(UnboundIdContainer container) {
        return new DefaultSpringSecurityContextSource(
                "ldap://localhost:" + container.getPort() + "/dc=springframework,dc=org");
    }

    @Bean
    BindAuthenticator authenticator(BaseLdapPathContextSource contextSource) {
        BindAuthenticator authenticator = new BindAuthenticator(contextSource);
        authenticator.setUserDnPatterns(new String[]{"uid={0},ou=people"});
        return authenticator;
    }

    @Bean
    LdapAuthenticationProvider authenticationProvider(LdapAuthenticator authenticator) {
        return new LdapAuthenticationProvider(authenticator);
    }

}
