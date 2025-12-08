package ao.sudojed.lss.jwt;

import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ao.sudojed.lss.core.LazySecurityProperties;
import ao.sudojed.lss.core.LazyUser;
import ao.sudojed.lss.exception.LazySecurityException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.Keys;

/**
 * Implementação padrão do JwtProvider usando JJWT.
 * Funciona out-of-the-box com configuração mínima.
 *
 * @author Sudojed Team
 */
public class DefaultJwtProvider implements JwtProvider {

    private static final Logger log = LoggerFactory.getLogger(DefaultJwtProvider.class);

    private static final String CLAIM_ROLES = "roles";
    private static final String CLAIM_PERMISSIONS = "permissions";
    private static final String CLAIM_USER_ID = "userId";
    private static final String CLAIM_USERNAME = "username";
    private static final String CLAIM_TOKEN_TYPE = "type";

    private final LazySecurityProperties.Jwt jwtConfig;
    private final SecretKey secretKey;

    public DefaultJwtProvider(LazySecurityProperties properties) {
        this.jwtConfig = properties.getJwt();
        this.secretKey = createSecretKey(jwtConfig.getSecret());
    }

    private SecretKey createSecretKey(String secret) {
        if (secret == null || secret.isBlank()) {
            throw new LazySecurityException("JWT secret não configurado. Configure 'lazy.security.jwt.secret'");
        }
        
        byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
        
        // Garante pelo menos 256 bits para HS256
        if (keyBytes.length < 32) {
            log.warn("JWT secret com menos de 256 bits. Recomendado usar pelo menos 32 caracteres.");
            // Padding para garantir segurança mínima
            byte[] paddedKey = new byte[32];
            System.arraycopy(keyBytes, 0, paddedKey, 0, keyBytes.length);
            keyBytes = paddedKey;
        }
        
        return Keys.hmacShaKeyFor(keyBytes);
    }

    @Override
    public String generateToken(LazyUser user) {
        return generateToken(user, Collections.emptyMap());
    }

    @Override
    public String generateToken(LazyUser user, Map<String, Object> extraClaims) {
        Date now = new Date();
        Date expiration = new Date(now.getTime() + jwtConfig.getExpiration());

        Map<String, Object> claims = new HashMap<>(extraClaims);
        claims.put(CLAIM_USER_ID, user.getId());
        claims.put(CLAIM_USERNAME, user.getUsername());
        claims.put(CLAIM_ROLES, user.getRoles());
        claims.put(CLAIM_PERMISSIONS, user.getPermissions());
        claims.put(CLAIM_TOKEN_TYPE, "access");
        
        // Adiciona claims do usuário
        claims.putAll(user.getClaims());

        JwtBuilder builder = Jwts.builder()
                .claims(claims)
                .subject(user.getId())
                .issuedAt(now)
                .expiration(expiration)
                .signWith(secretKey);

        if (jwtConfig.getIssuer() != null && !jwtConfig.getIssuer().isBlank()) {
            builder.issuer(jwtConfig.getIssuer());
        }

        if (jwtConfig.getAudience() != null && !jwtConfig.getAudience().isBlank()) {
            builder.audience().add(jwtConfig.getAudience());
        }

        return builder.compact();
    }

    @Override
    public String generateRefreshToken(LazyUser user) {
        Date now = new Date();
        Date expiration = new Date(now.getTime() + jwtConfig.getRefreshExpiration());

        return Jwts.builder()
                .subject(user.getId())
                .claim(CLAIM_TOKEN_TYPE, "refresh")
                .issuedAt(now)
                .expiration(expiration)
                .signWith(secretKey)
                .compact();
    }

    @Override
    public LazyUser validateToken(String token) {
        try {
            Claims claims = parseToken(token);
            
            String tokenType = claims.get(CLAIM_TOKEN_TYPE, String.class);
            if ("refresh".equals(tokenType)) {
                throw new LazySecurityException("Refresh token não pode ser usado para autenticação");
            }

            return buildUserFromClaims(claims);
        } catch (ExpiredJwtException e) {
            throw new LazySecurityException("Token expirado", e);
        } catch (MalformedJwtException e) {
            throw new LazySecurityException("Token mal formatado", e);
        } catch (SecurityException e) {
            throw new LazySecurityException("Assinatura do token inválida", e);
        } catch (Exception e) {
            throw new LazySecurityException("Token inválido: " + e.getMessage(), e);
        }
    }

    @Override
    public boolean isTokenValid(String token) {
        try {
            parseToken(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public boolean isTokenExpired(String token) {
        try {
            Claims claims = parseToken(token);
            return claims.getExpiration().before(new Date());
        } catch (ExpiredJwtException e) {
            return true;
        } catch (Exception e) {
            return true;
        }
    }

    @Override
    public String extractSubject(String token) {
        return parseToken(token).getSubject();
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> T extractClaim(String token, String claimName, Class<T> type) {
        Claims claims = parseToken(token);
        return claims.get(claimName, type);
    }

    @Override
    public Map<String, Object> extractAllClaims(String token) {
        return new HashMap<>(parseToken(token));
    }

    @Override
    public String refreshToken(String refreshToken) {
        try {
            Claims claims = parseToken(refreshToken);
            
            String tokenType = claims.get(CLAIM_TOKEN_TYPE, String.class);
            if (!"refresh".equals(tokenType)) {
                throw new LazySecurityException("Token fornecido não é um refresh token");
            }

            String userId = claims.getSubject();
            
            // Cria um usuário básico para gerar novo token
            // Em uma implementação real, você buscaria o usuário do banco
            LazyUser user = LazyUser.builder()
                    .id(userId)
                    .username(userId)
                    .build();

            return generateToken(user);
        } catch (ExpiredJwtException e) {
            throw new LazySecurityException("Refresh token expirado", e);
        }
    }

    private Claims parseToken(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    @SuppressWarnings("unchecked")
    private LazyUser buildUserFromClaims(Claims claims) {
        String userId = claims.get(CLAIM_USER_ID, String.class);
        String username = claims.get(CLAIM_USERNAME, String.class);
        
        Collection<String> roles = claims.get(CLAIM_ROLES, Collection.class);
        Collection<String> permissions = claims.get(CLAIM_PERMISSIONS, Collection.class);

        LazyUser.Builder builder = LazyUser.builder()
                .id(userId != null ? userId : claims.getSubject())
                .username(username != null ? username : claims.getSubject())
                .authenticated(true);

        if (roles != null) {
            builder.roles(roles.stream()
                    .map(Object::toString)
                    .collect(Collectors.toSet()));
        }

        if (permissions != null) {
            builder.permissions(permissions.stream()
                    .map(Object::toString)
                    .collect(Collectors.toSet()));
        }

        // Adiciona outros claims como claims customizados
        claims.forEach((key, value) -> {
            if (!isReservedClaim(key)) {
                builder.claim(key, value);
            }
        });

        return builder.build();
    }

    private boolean isReservedClaim(String claim) {
        return Set.of(
                Claims.SUBJECT, Claims.ISSUED_AT, Claims.EXPIRATION, 
                Claims.ISSUER, Claims.AUDIENCE,
                CLAIM_USER_ID, CLAIM_USERNAME, CLAIM_ROLES, 
                CLAIM_PERMISSIONS, CLAIM_TOKEN_TYPE
        ).contains(claim);
    }
}
