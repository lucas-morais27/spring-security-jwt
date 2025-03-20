package spring.security.jwt.security;

import jakarta.servlet.annotation.WebServlet;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    @Bean
    public BCryptPasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }

    private static final String[] SWAGGER_WHITELIST = {
            "/v2/api-docs",
            "/swagger-resources",
            "/swagger-resources/**",
            "/configuration/ui",
            "/configuration/security",
            "/swagger-ui.html",
            "/webjars/**"
    };

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable) // Desabilita CSRF, necessário para APIs REST
                .addFilterAfter(new JWTFilter(), UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers(SWAGGER_WHITELIST).permitAll()  // Permite o acesso ao Swagger sem autenticação
                        .requestMatchers("/h2-console/**").permitAll()  // Permite o acesso ao console do H2
                        .requestMatchers(HttpMethod.POST, "/login").permitAll()  // Permite login sem autenticação
                        .requestMatchers(HttpMethod.POST, "/users").permitAll()  // Permite a criação de usuários
                        .requestMatchers(HttpMethod.GET, "/users").hasAnyRole("USERS", "MANAGERS")  // Acesso limitado aos usuários com os papéis apropriados
                        .requestMatchers("/managers").hasRole("MANAGERS")  // Apenas usuários com o papel 'MANAGERS' podem acessar esta rota
                        .anyRequest().authenticated()  // Exige autenticação para qualquer outra requisição
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));  // Desabilita a sessão, tornando a aplicação sem estado

        return http.build();
    }

    @Bean //HABILITANDO ACESSAR O H2-DATABSE NA WEB
    public ServletRegistrationBean h2servletRegistration(){
        ServletRegistrationBean registrationBean = new ServletRegistrationBean( new WebServlet());
        registrationBean.addUrlMappings("/h2-console/*");
        return registrationBean;
    }
}
