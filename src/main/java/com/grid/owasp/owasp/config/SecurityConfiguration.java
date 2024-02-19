
package com.grid.owasp.owasp.config;
/*
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import springfox.documentation.oas.annotations.EnableOpenApi;
*/

import com.grid.owasp.owasp.CredentialsStuffingService;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {


    @Autowired
    private CredentialsStuffingService credentialsStuffingService;

   /* public void credentialsStuffingService(CredentialsStuffingService credentialsStuffingService) {
          this.credentialsStuffingService = credentialsStuffingService;
    }*/

    @PostConstruct
    public  void loadData() {
        System.out.println("@POst construct called");
        credentialsStuffingService.loadData();
    }


    /*@Bean
    public static PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    //add custom users
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails userDetailsAdmin = User.builder()
                .password(passwordEncoder().encode("admin")).username("admin").roles("ADMIN").build();

        UserDetails userDetailsRoot = User.builder().password(passwordEncoder().encode("root")).username("root").roles("ADMIN").build();

        return new InMemoryUserDetailsManager(userDetailsAdmin, userDetailsRoot);
    }

   */
/* @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        //http.csrf().disable()

        http.csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests((authorize) ->
                                authorize.anyRequest().authenticated()
                        *//*
     */
/*authorize.requestMatchers("/register/**").permitAll()
                                .requestMatchers("/index").permitAll()
                                .requestMatchers("/h2-console").permitAll()
                                .requestMatchers("/login").permitAll()
                                .requestMatchers("/users").hasRole("ADMIN")*//*
     */
/*
                ).httpBasic(Customizer.withDefaults());
        *//*
     */
    /*.formLogin(Customizer.withDefaults())
     *//*
     */
    /**//*
     */
/*form -> form
                                .loginPage("/login")
                                .loginProcessingUrl("/login")
                                .defaultSuccessUrl("/users")
                                .usernameParameter("user")
                                .passwordParameter("pass")
                                .permitAll()
                )*//*
     */
    /**//*
     */
/*.logout(
                        logout -> logout
                                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                                .permitAll()
                );*//*
     */
/*
        return http.build();
    }*//*


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests((authorize) ->
                        authorize.requestMatchers("/entrypoint/**").permitAll()
                                .requestMatchers("/entrypoint/reset-password").authenticated()
                                .requestMatchers("/entrypoint/reset-password-with-ratelimit").permitAll())
                .formLogin(Customizer.withDefaults());
        return http.build();
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth
                //.userDetailsService(userDetailsService)
                .inMemoryAuthentication().withUser("user").password(passwordEncoder().encode("pass")).roles("ADMIN");
        //.passwordEncoder(passwordEncoder());
    }


}
*/
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeRequests().anyRequest().permitAll().and().build();
    }


    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception
    {
        auth.inMemoryAuthentication()
                .withUser("user")
                .password("pass")
                .roles("ADMIN");
    }
}