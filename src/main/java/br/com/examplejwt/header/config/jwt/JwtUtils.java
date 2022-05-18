package br.com.examplejwt.header.config.jwt;

import br.com.examplejwt.header.service.impl.UserDetailsImpl;
import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Date;

import static io.jsonwebtoken.SignatureAlgorithm.HS512;

/**
 * Utilitário responsável por criar, obter, validar, converter informações do Token em conteúdo, ou conteúdo num token.
 * <br />
 * Utility responsible for creating, obtaining, validating, converting Token information into content, or content into a token
 *
 * @author Marcio
 */
@Component
public class JwtUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtUtils.class);

    @SuppressWarnings("UnusedDeclaration")
    @Value("${example.jwt.secret}")
    private String jwtSecret;

    @SuppressWarnings("UnusedDeclaration")
    @Value("${example.jwt.expirationMs}")
    private int jwtExpirationMs;


    public String generateJwtToken(final Authentication authentication) {
        final UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        final Date dateActual = new Date();

        return Jwts.builder()
                .setSubject(userDetails.getUsername())
                .setIssuedAt(dateActual)
                .setExpiration(new Date(dateActual.getTime() + jwtExpirationMs))
                .signWith(HS512, jwtSecret)
                .compact();
    }

    public String getUserNameFromJwtToken(final String token) {
        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
    }

    public boolean validateJwtToken(final String authToken) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException e) {
            LOGGER.error("Invalid JWT signature: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            LOGGER.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            LOGGER.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            LOGGER.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            LOGGER.error("JWT claims string is empty: {}", e.getMessage());
        }
        return false;
    }
}
