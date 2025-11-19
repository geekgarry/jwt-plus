package com.github.plusplus.exceptions;

/**
 * author     : geekplus
 * email      :
 * date       : 9/9/25 3:10 PM
 * description: //TODO
 */
public class InvalidClaimException extends JWTVerificationException {
    public InvalidClaimException(String message) {
        super(message);
    }
}
