package com.emna.films.security;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;



import javax.sql.DataSource;
import java.util.Arrays;

@Configuration 
@EnableWebSecurity
public class SecurityConfig { 
  
    /*@Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.cors(Customizer.withDefaults()) // Active la configuration CORS
            .authorizeHttpRequests((requests)->requests
                .requestMatchers("/modifierFilm","/supprimerFilm").hasAnyAuthority("ADMIN")
                .requestMatchers("/showCreate","/saveFilm").hasAnyAuthority("ADMIN","AGENT")
                .requestMatchers("/ListeFilms").hasAnyAuthority("ADMIN","AGENT","USER")
                .requestMatchers("/login","/webjars/**","/api/**","/genre/**").permitAll() 
                .anyRequest().authenticated())
            .csrf(csrf->csrf.disable())
            .formLogin((formLogin) -> formLogin 
                .loginPage("/login") 
                .defaultSuccessUrl("/"))
            .httpBasic(Customizer.withDefaults())
            .exceptionHandling((exception)-> exception.accessDeniedPage("/accessDenied"));
        return http.build();
    }
    
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:4200")); // Autorise Angular
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }*/

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
	@Bean 
	 public SecurityFilterChain filterChain (HttpSecurity http) throws 
	Exception 
	 { 
	  http.sessionManagement( session ->  
	  session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) 
	  .csrf( csrf -> csrf.disable())  
	            .authorizeHttpRequests( requests -> 
	requests.requestMatchers("/api/all/**").hasAnyAuthority("ADMINE","USER")
			.requestMatchers(HttpMethod.GET, "/api/getbyid/**").hasAnyAuthority("ADMINE","USER")
			.requestMatchers(HttpMethod.POST, "/api/addfilm/**").hasAnyAuthority("ADMINE")
			.requestMatchers(HttpMethod.PUT, "/api/updatefilm/**").hasAnyAuthority("ADMINE")
			.requestMatchers(HttpMethod.DELETE, "/api/delfilm/**").hasAnyAuthority("ADMINE")
	.anyRequest().authenticated() )
	.addFilterBefore(new JWTAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);
	  
	   
	 return http.build(); 
	 } 
	
}