package br.com.examplejwt.header.controller;

import br.com.examplejwt.header.config.jwt.JwtUtils;
import br.com.examplejwt.header.model.dto.request.LoginRequest;
import br.com.examplejwt.header.model.dto.request.SignupRequest;
import br.com.examplejwt.header.model.dto.response.JwtResponse;
import br.com.examplejwt.header.model.dto.response.MessageResponse;
import br.com.examplejwt.header.model.entity.Role;
import br.com.examplejwt.header.model.entity.User;
import br.com.examplejwt.header.repository.RoleRepository;
import br.com.examplejwt.header.repository.UserRepository;
import br.com.examplejwt.header.service.impl.UserDetailsImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static br.com.examplejwt.header.model.enums.ERole.*;
import static java.lang.Boolean.TRUE;
import static java.util.Objects.isNull;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

/**
 * Controller responsável por viabilizar trocas de informações para fins de autenticação. <br />
 *
 * Controller responsible for enabling information exchange for authentication purposes.
 *
 * @author Marcio
 */
@SuppressWarnings("unused")
@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private static final String ROLE_NOT_FOUND = "Error: Role is not found.";

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder encoder;
    private final JwtUtils jwtUtils;

    @PostMapping(value = "/signin", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        final Authentication authenticate = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authenticate);

        final UserDetailsImpl userDetails = (UserDetailsImpl) authenticate.getPrincipal();

        final String jwt = jwtUtils.generateJwtToken(authenticate);

        final List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        return ResponseEntity.ok(JwtResponse.builder()
                .token(jwt)
                .id(userDetails.getId())
                .username(userDetails.getUsername())
                .email(userDetails.getEmail())
                .roles(roles)
                .build());
    }

    @PostMapping(value = "/signup", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> registerUser(@Valid @RequestBody SignupRequest signupRequest) {
        if(TRUE.equals(userRepository.existsByUsername(signupRequest.getUsername()))) {
            return ResponseEntity.badRequest().body(MessageResponse.builder().message("Error: Username is already").build());
        }
        if (TRUE.equals(userRepository.existsByEmail(signupRequest.getEmail()))) {
            return ResponseEntity.badRequest().body(MessageResponse.builder().message("Error: E-mail is already").build());
        }

        final User user = User.builder()
                .username(signupRequest.getUsername())
                .email(signupRequest.getEmail())
                .password(encoder.encode(signupRequest.getPassword()))
                .build();

        final Set<String> signRoles = signupRequest.getRole();
        final Set<Role> roles = new HashSet<>();

        if (isNull(signRoles)) {
            roles.add(roleRepository.findByName(ROLE_USER)
                    .orElseThrow(() -> new RuntimeException(ROLE_NOT_FOUND)));
        } else {
            signRoles.forEach(role -> {
                switch (role) {
                    case "admin" -> roles.add(roleRepository.findByName(ROLE_ADMIN)
                            .orElseThrow(() -> new RuntimeException(ROLE_NOT_FOUND)));
                    case "mod" -> roles.add(roleRepository.findByName(ROLE_MODERATOR)
                            .orElseThrow(() -> new RuntimeException(ROLE_NOT_FOUND)));
                    default -> roles.add(roleRepository.findByName(ROLE_USER)
                            .orElseThrow(() -> new RuntimeException(ROLE_NOT_FOUND)));
                }
            });
        }
        user.setRoles(roles);
        userRepository.save(user);
        return ResponseEntity.ok(MessageResponse.builder().message("User registered!").build());
    }
}
