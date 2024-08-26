package cyber.login.jwt.system.loginsystemjwt.auth.services;

import java.sql.Date;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;

import cyber.login.jwt.system.loginsystemjwt.security.TokenService;
import cyber.login.jwt.system.loginsystemjwt.user.dtos.AuthetinticationDto;
import cyber.login.jwt.system.loginsystemjwt.user.dtos.LoginResponseDto;
import cyber.login.jwt.system.loginsystemjwt.user.dtos.RegisterDto;
import cyber.login.jwt.system.loginsystemjwt.user.models.UserModel;
import cyber.login.jwt.system.loginsystemjwt.user.repositories.UserRepository;
import cyber.login.jwt.system.loginsystemjwt.emails.EmailService;
import jakarta.validation.Valid;

@Service
public class AuthorizationService implements UserDetailsService {
    @Autowired
    private ApplicationContext context;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TokenService tokenService;

    @Autowired
    private EmailService emailService;  // Serviço de envio de e-mails

    private AuthenticationManager authenticationManager;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return userRepository.findByEmail(email);
    }

    public ResponseEntity<Object> login(@RequestBody @Valid AuthetinticationDto data) {
        authenticationManager = context.getBean(AuthenticationManager.class);

        var user = (UserModel) this.loadUserByUsername(data.email());

        if (!user.isEmailVerified()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("E-mail não verificado.");
        }

        var usernamePassword = new UsernamePasswordAuthenticationToken(data.email(), data.password());
        var auth = this.authenticationManager.authenticate(usernamePassword);
        var token = tokenService.generateToken(user);

        return ResponseEntity.ok(new LoginResponseDto(token));
    }

    public ResponseEntity<Object> register(@RequestBody @Valid RegisterDto registerDto) {
        if (this.userRepository.findByEmail(registerDto.email()) != null) {
            return ResponseEntity.badRequest().build();
        }

        String encryptedPassword = new BCryptPasswordEncoder().encode(registerDto.password());

        UserModel newUser = new UserModel(registerDto.email(), encryptedPassword, registerDto.role());
        newUser.setCreatedAt(new Date(System.currentTimeMillis()));
        newUser.setEmailVerified(false);  // Email inicialmente não verificado
        this.userRepository.save(newUser);

        String verificationToken = tokenService.generateVerificationToken(newUser);

        // Enviar o e-mail com o link de verificação
        String verificationLink = "http://localhost:8080/auth/verify-email?token=" + verificationToken;
        emailService.sendEmail(registerDto.email(), "Verificação de E-mail",
                "Clique no link para verificar seu e-mail: " + verificationLink);

        return ResponseEntity.ok("Cadastro realizado com sucesso. Verifique seu e-mail.");
    }

    public ResponseEntity<String> verifyEmail(String token) {
        String email = tokenService.validateVerificationToken(token);

        if (email != null) {
            UserModel user = (UserModel) userRepository.findByEmail(email);
            user.setEmailVerified(true);  // Marca o e-mail como verificado
            userRepository.save(user);
            return ResponseEntity.ok("E-mail verificado com sucesso.");
        } else {
            return ResponseEntity.badRequest().body("Token de verificação inválido.");
        }
    }
}
