package cyber.login.jwt.system.loginsystemjwt.auth.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import cyber.login.jwt.system.loginsystemjwt.auth.services.AuthorizationService;
import cyber.login.jwt.system.loginsystemjwt.user.dtos.AuthetinticationDto;
import cyber.login.jwt.system.loginsystemjwt.user.dtos.RegisterDto;
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
    public ResponseEntity<Object> register(@RequestBody @Valid RegisterDto registerDto) {
        return authorizationService.register(registerDto);
    }

    @GetMapping("/verify-email")
    public ResponseEntity<String> verifyEmail(@RequestParam String token) {
        return authorizationService.verifyEmail(token);
    }
}
