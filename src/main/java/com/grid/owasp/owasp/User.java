package com.grid.owasp.owasp;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NonNull;

@Builder
@Data
public class User {

    @NonNull
    String userName;

    @Builder.Default
    String password = null;

    @Builder.Default
    int otpCode = 0;
}
