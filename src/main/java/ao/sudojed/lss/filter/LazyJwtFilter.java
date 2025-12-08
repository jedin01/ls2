package ao.sudojed.lss.filter;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import ao.sudojed.lss.core.LazySecurityContext;
import ao.sudojed.lss.core.LazySecurityProperties;
import ao.sudojed.lss.core.LazyUser;
import ao.sudojed.lss.exception.LazySecurityException;
import ao.sudojed.lss.exception.LazySecurityExceptionHandler;
import ao.sudojed.lss.jwt.JwtProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Filtro JWT do LazySpringSecurity.
 * Intercepta requests, extrai e valida tokens JWT automaticamente.
 *
 * @author Sudojed Team
 */
public class LazyJwtFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(LazyJwtFilter.class);

    private final JwtProvider jwtProvider;
    private final LazySecurityProperties properties;
    private final LazySecurityExceptionHandler exceptionHandler;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    public LazyJwtFilter(JwtProvider jwtProvider, LazySecurityProperties properties) {
        this.jwtProvider = jwtProvider;
        this.properties = properties;
        this.exceptionHandler = new LazySecurityExceptionHandler();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        try {
            // Verifica se é path público
            if (isPublicPath(request.getRequestURI())) {
                if (properties.isDebug()) {
                    log.debug("Public path accessed: {}", request.getRequestURI());
                }
                filterChain.doFilter(request, response);
                return;
            }

            // Extrai token do header
            String token = extractToken(request);

            if (token != null) {
                processToken(request, token);
            }

            filterChain.doFilter(request, response);

        } catch (LazySecurityException e) {
            exceptionHandler.handleLazyException(request, response, e);
        } finally {
            // Limpa contexto
            LazySecurityContext.clear();
        }
    }

    private String extractToken(HttpServletRequest request) {
        String header = request.getHeader(properties.getJwt().getHeader());
        
        if (StringUtils.hasText(header)) {
            String prefix = properties.getJwt().getPrefix();
            if (header.startsWith(prefix)) {
                return header.substring(prefix.length());
            }
            // Aceita token sem prefixo também
            return header;
        }
        
        // Fallback: tenta extrair de query param (útil para WebSocket)
        String tokenParam = request.getParameter("token");
        if (StringUtils.hasText(tokenParam)) {
            return tokenParam;
        }

        return null;
    }

    private void processToken(HttpServletRequest request, String token) {
        LazyUser user = jwtProvider.validateToken(token);
        
        // Define no contexto do LSS
        LazySecurityContext.setCurrentUser(user);

        // Define no contexto do Spring Security
        List<SimpleGrantedAuthority> authorities = Stream.concat(
                user.getRoles().stream().map(role -> new SimpleGrantedAuthority("ROLE_" + role)),
                user.getPermissions().stream().map(SimpleGrantedAuthority::new)
        ).collect(Collectors.toList());

        UsernamePasswordAuthenticationToken authentication = 
                new UsernamePasswordAuthenticationToken(user, null, authorities);
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        if (properties.isDebug()) {
            log.debug("User authenticated: {} with roles: {}", user.getUsername(), user.getRoles());
        }
    }

    private boolean isPublicPath(String requestPath) {
        return properties.getPublicPaths().stream()
                .anyMatch(pattern -> pathMatcher.match(pattern, requestPath));
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // Não filtra OPTIONS (preflight CORS)
        return "OPTIONS".equalsIgnoreCase(request.getMethod());
    }
}
