package com.github.plusplus.exceptions;

/**
 * author     : geekplus
 * email      :
 * date       : 9/9/25 2:26 PM
 * description: //TODO
 */
public class TokenExpiredException  extends JWTVerificationException{
    private static final long serialVersionUID = 1L;

    public TokenExpiredException(String message) {
        super(message);
    }
}
