package cyber.login.jwt.system.loginsystemjwt.user.dtos;

import cyber.login.jwt.system.loginsystemjwt.user.enums.UserRole;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

public record RegisterDto(
        @NotNull String email,
        @NotNull
        @Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d{2})([a-zA-Z0-9]{8})$",
                message = "A senha deve conter 8 caracteres, sendo pelo menos 1 letra maiúscula, 1 letra minúscula, 2 números e o restante letras ou números.")
        String password,

        @NotNull UserRole role
) {}
