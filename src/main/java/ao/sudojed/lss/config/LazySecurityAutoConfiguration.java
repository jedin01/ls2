package ao.sudojed.lss.config;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportAware;
import org.springframework.core.annotation.AnnotationAttributes;
import org.springframework.core.env.Environment;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import ao.sudojed.lss.annotation.EnableLazySecurity;
import ao.sudojed.lss.aspect.LazySecurityAspect;
import ao.sudojed.lss.aspect.RateLimitAspect;
import ao.sudojed.lss.core.LazySecurityProperties;
import ao.sudojed.lss.exception.LazySecurityExceptionHandler;
import ao.sudojed.lss.filter.LazyJwtFilter;
import ao.sudojed.lss.filter.RateLimitManager;
import ao.sudojed.lss.jwt.DefaultJwtProvider;
import ao.sudojed.lss.jwt.JwtProvider;
import ao.sudojed.lss.jwt.JwtService;
import ao.sudojed.lss.resolver.LazyUserArgumentResolver;

/**
 * Auto-configuração do LazySpringSecurity.
 * Configura Spring Security por baixo dos panos de forma transparente.
 *
 * @author Sudojed Team
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@EnableConfigurationProperties(LazySecurityProperties.class)
public class LazySecurityAutoConfiguration implements ImportAware, WebMvcConfigurer {

    private static final Logger log = LoggerFactory.getLogger(LazySecurityAutoConfiguration.class);

    private AnnotationAttributes enableLazySecurityAttributes;

    @Autowired
    private Environment environment;

    @Autowired
    private LazySecurityProperties properties;

    @Override
    public void setImportMetadata(AnnotationMetadata importMetadata) {
        Map<String, Object> annotationAttributes = importMetadata.getAnnotationAttributes(
                EnableLazySecurity.class.getName());
        
        if (annotationAttributes != null) {
            this.enableLazySecurityAttributes = AnnotationAttributes.fromMap(annotationAttributes);
            mergeAnnotationWithProperties();
        }
    }

    /**
     * Mescla configurações da annotation @EnableLazySecurity com application.yml.
     * Annotation tem prioridade sobre properties.
     */
    private void mergeAnnotationWithProperties() {
        if (enableLazySecurityAttributes == null) {
            return;
        }

        // Public paths
        String[] annotationPublicPaths = enableLazySecurityAttributes.getStringArray("publicPaths");
        if (annotationPublicPaths.length > 0) {
            List<String> merged = new ArrayList<>(properties.getPublicPaths());
            merged.addAll(Arrays.asList(annotationPublicPaths));
            properties.setPublicPaths(merged);
        }

        // Default role
        String defaultRole = enableLazySecurityAttributes.getString("defaultRole");
        if (!defaultRole.isEmpty() && !"USER".equals(defaultRole)) {
            properties.setDefaultRole(defaultRole);
        }

        // CSRF
        properties.setCsrfEnabled(enableLazySecurityAttributes.getBoolean("csrfEnabled"));

        // CORS
        properties.getCors().setEnabled(enableLazySecurityAttributes.getBoolean("corsEnabled"));
        
        String[] corsOrigins = enableLazySecurityAttributes.getStringArray("corsOrigins");
        if (corsOrigins.length > 0) {
            properties.getCors().setOrigins(Arrays.asList(corsOrigins));
        }
        
        String[] corsMethods = enableLazySecurityAttributes.getStringArray("corsMethods");
        if (corsMethods.length > 0) {
            properties.getCors().setMethods(Arrays.asList(corsMethods));
        }

        // JWT Config
        AnnotationAttributes jwtAttributes = enableLazySecurityAttributes.getAnnotation("jwt");
        if (jwtAttributes != null) {
            String secret = jwtAttributes.getString("secret");
            if (!secret.isEmpty()) {
                // Resolve placeholders do Spring (${JWT_SECRET})
                String resolvedSecret = environment.resolvePlaceholders(secret);
                properties.getJwt().setSecret(resolvedSecret);
            }

            long expiration = jwtAttributes.getNumber("expiration");
            if (expiration > 0) {
                properties.getJwt().setExpiration(expiration);
            }

            long refreshExpiration = jwtAttributes.getNumber("refreshExpiration");
            if (refreshExpiration > 0) {
                properties.getJwt().setRefreshExpiration(refreshExpiration);
            }

            String header = jwtAttributes.getString("header");
            if (!header.isEmpty()) {
                properties.getJwt().setHeader(header);
            }

            String prefix = jwtAttributes.getString("prefix");
            if (!prefix.isEmpty()) {
                properties.getJwt().setPrefix(prefix);
            }

            String issuer = jwtAttributes.getString("issuer");
            if (!issuer.isEmpty()) {
                properties.getJwt().setIssuer(issuer);
            }
        }

        // Debug mode
        properties.setDebug(enableLazySecurityAttributes.getBoolean("debug"));

        if (properties.isDebug()) {
            log.info("LazySpringSecurity configured with:");
            log.info("  Public paths: {}", properties.getPublicPaths());
            log.info("  Default role: {}", properties.getDefaultRole());
            log.info("  CSRF enabled: {}", properties.isCsrfEnabled());
            log.info("  CORS enabled: {}", properties.getCors().isEnabled());
            log.info("  JWT issuer: {}", properties.getJwt().getIssuer());
        }
    }

    // ==================== Beans ====================

    @Bean
    @ConditionalOnMissingBean
    public JwtProvider jwtProvider() {
        return new DefaultJwtProvider(properties);
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtService jwtService(JwtProvider jwtProvider) {
        return new JwtService(jwtProvider, properties);
    }

    @Bean
    public LazyJwtFilter lazyJwtFilter(JwtProvider jwtProvider) {
        return new LazyJwtFilter(jwtProvider, properties);
    }

    @Bean
    public LazySecurityExceptionHandler lazySecurityExceptionHandler() {
        return new LazySecurityExceptionHandler();
    }

    @Bean
    public RateLimitManager rateLimitManager() {
        return new RateLimitManager();
    }

    @Bean
    public LazySecurityAspect lazySecurityAspect() {
        return new LazySecurityAspect();
    }

    @Bean
    public RateLimitAspect rateLimitAspect(RateLimitManager rateLimitManager) {
        return new RateLimitAspect(rateLimitManager);
    }

    @Bean
    public LazyUserArgumentResolver lazyUserArgumentResolver() {
        return new LazyUserArgumentResolver();
    }

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
        resolvers.add(lazyUserArgumentResolver());
    }

    // ==================== Security Filter Chain ====================

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, LazyJwtFilter jwtFilter,
                                                   LazySecurityExceptionHandler exceptionHandler) throws Exception {
        
        // CSRF
        if (!properties.isCsrfEnabled()) {
            http.csrf(AbstractHttpConfigurer::disable);
        }

        // CORS
        if (properties.getCors().isEnabled()) {
            http.cors(cors -> cors.configurationSource(corsConfigurationSource()));
        } else {
            http.cors(AbstractHttpConfigurer::disable);
        }

        // Session stateless (JWT)
        http.sessionManagement(session -> 
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // Authorization
        http.authorizeHttpRequests(auth -> {
            // Public paths
            for (String path : properties.getPublicPaths()) {
                auth.requestMatchers(path).permitAll();
            }
            // Demais requerem autenticação
            auth.anyRequest().authenticated();
        });

        // Exception handling
        http.exceptionHandling(ex -> ex
                .authenticationEntryPoint(exceptionHandler)
                .accessDeniedHandler(exceptionHandler));

        // JWT Filter
        http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        log.info("LazySpringSecurity initialized successfully!");
        
        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(properties.getCors().getOrigins());
        configuration.setAllowedMethods(properties.getCors().getMethods());
        configuration.setAllowedHeaders(properties.getCors().getHeaders());
        configuration.setAllowCredentials(properties.getCors().isAllowCredentials());
        configuration.setMaxAge(properties.getCors().getMaxAge());

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
