package com.grid.owasp.owasp;

import lombok.Builder;
import lombok.NonNull;

@Builder
public class User {

    @NonNull
    String userName;

    @Builder.Default
    String password = null;

    @Builder.Default
    int otpCode = 0;
}
