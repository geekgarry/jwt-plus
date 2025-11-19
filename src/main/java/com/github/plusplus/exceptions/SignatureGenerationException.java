package com.github.plusplus.exceptions;

import com.github.plusplus.algorithm.Algorithm;

/**
 * author     : geekplus
 * email      :
 * date       : 9/9/25 2:31 PM
 * description: //TODO
 */
public class SignatureGenerationException extends JWTCreationException {
    public SignatureGenerationException(Algorithm algorithm, Throwable cause) {
        super("The Token's Signature couldn't be generated when signing using the Algorithm: " + algorithm, cause);
    }
}
