package cyber.login.jwt.system.loginsystemjwt.auth.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import cyber.login.jwt.system.loginsystemjwt.auth.services.AuthorizationService;
import cyber.login.jwt.system.loginsystemjwt.security.TokenService;
import cyber.login.jwt.system.loginsystemjwt.user.dtos.AuthetinticationDto;
import cyber.login.jwt.system.loginsystemjwt.user.dtos.LoginResponseDto;
import cyber.login.jwt.system.loginsystemjwt.user.dtos.RegisterDto;
import cyber.login.jwt.system.loginsystemjwt.user.models.UserModel;
import cyber.login.jwt.system.loginsystemjwt.user.repositories.UserRepository;
import jakarta.validation.Valid;

@RestController
@RequestMapping("auth")
public class AuthController {
   
    @Autowired
    AuthorizationService authorizationService;

    @PostMapping("/login")
    public ResponseEntity<Object> login(@RequestBody @Valid AuthetinticationDto authetinticationDto){
        return authorizationService.login(authetinticationDto);
    }


    @PostMapping("/register")
    public ResponseEntity<Object> register (@RequestBody RegisterDto registerDto){
        return authorizationService.register(registerDto);
    }
}
