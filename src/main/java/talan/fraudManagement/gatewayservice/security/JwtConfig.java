package talan.fraudManagement.gatewayservice.security;



import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;



import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import lombok.Data;

@Component
@Data

public class JwtConfig {
	@Value("${security.jwt.uri:/auth/**}")
    private String Uri;

    @Value("${security.jwt.header:Authorization}")
    private String header;

    @Value("${security.jwt.prefix:Bearer }")
    private String prefix;

    @Value("${talan.app.jwtSecret}")
	private String jwtSecret;

	@Value("${talan.app.jwtExpirationMs}")
	private int jwtExpirationMs;
	private static final Logger logger = LoggerFactory.getLogger(JwtConfig.class);
	public String getUserNameFromJwtToken(String token) {
		return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
	}

	public boolean validateJwtToken(String authToken) {
		try {
			Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
			return true;
		} catch (SignatureException e) {
			logger.error("Invalid JWT signature: {}", e.getMessage());
		} catch (MalformedJwtException e) {
			logger.error("Invalid JWT token: {}", e.getMessage());
		} catch (ExpiredJwtException e) {
			logger.error("JWT token is expired: {}", e.getMessage());
		} catch (UnsupportedJwtException e) {
			logger.error("JWT token is unsupported: {}", e.getMessage());
		} catch (IllegalArgumentException e) {
			logger.error("JWT claims string is empty: {}", e.getMessage());
		}

		return false;
	}
	
	public int getJwtExpirationMs() {
		// TODO Auto-generated method stub
		return this.jwtExpirationMs;
	}

	public String getJwtSecret() {
		// TODO Auto-generated method stub
		return this.jwtSecret;
	}

	public String getHeader() {
		// TODO Auto-generated method stub
		return this.header;
	}

	public String getPrefix() {
		// TODO Auto-generated method stub
		return this.prefix;
	}

	public String getUri() {
		// TODO Auto-generated method stub
		return this.Uri;
	}
}

