package com.github.plusplus.exceptions;

import com.github.plusplus.algorithm.Algorithm;

/**
 * author     : geekplus
 * email      :
 * date       : 9/9/25 2:29 PM
 * description: //TODO
 */
public class SignatureVerificationException extends JWTVerificationException {
    public SignatureVerificationException(Algorithm algorithm) {
        this(algorithm, (Throwable)null);
    }

    public SignatureVerificationException(Algorithm algorithm, Throwable cause) {
        super("The Token's Signature resulted invalid when verified using the Algorithm: " + algorithm, cause);
    }
}
