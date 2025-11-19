package com.github.plusplus.exceptions;

/**
 * author     : geekplus
 * email      :
 * date       : 9/9/25 2:34 PM
 * description: //TODO
 */
public class JWTDecodeException extends JWTVerificationException {
    public JWTDecodeException(String message) {
        this(message, (Throwable)null);
    }

    public JWTDecodeException(String message, Throwable cause) {
        super(message, cause);
    }
}
