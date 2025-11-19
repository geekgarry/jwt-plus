package com.github.plusplus.exceptions;

/**
 * author     : geekplus
 * email      :
 * date       : 9/9/25 2:26 PM
 * description: //TODO
 */
public class JWTVerificationException extends RuntimeException {
    public JWTVerificationException(String message) {
        this(message, (Throwable)null);
    }

    public JWTVerificationException(String message, Throwable cause) {
        super(message, cause);
    }
}
