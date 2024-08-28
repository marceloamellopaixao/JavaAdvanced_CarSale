package br.com.fiap.apicarsale.auth;

import br.com.fiap.apicarsale.domain.user.User;
import br.com.fiap.apicarsale.domain.user.UserRepository;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.ZoneOffset;

@Service
public class AuthService {

    public Algorithm ALGORITHM;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;

    public AuthService(@Value("${jwt.secret}") String secret, UserRepository userRepository, PasswordEncoder passwordEncoder, TokenService tokenService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenService = tokenService;
        ALGORITHM = Algorithm.HMAC256(secret);
    }

    public Token create(User user){
        var expiresAt = LocalDateTime.now().plusHours(1).toInstant(ZoneOffset.ofHours(-3));

        String token = JWT.create()
                .withIssuer("api-carsale")
                .withSubject(user.getUsername())
                .withClaim("role", "admin")
                .withExpiresAt(expiresAt)
                .sign(ALGORITHM);

        return new Token(token, user.getName(), user.getId().toString(), user.getRole());
    }

    public Token login(Credentials credentials) {
        var user = userRepository.findByUsername(credentials.username())
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!passwordEncoder.matches(credentials.password(), user.getPassword())) {
            throw new RuntimeException("Invalid password");
        }

        return tokenService.create(user);

    }

}
