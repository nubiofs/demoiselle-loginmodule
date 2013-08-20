package br.gov.frameworkdemoiselle.loginmodule;

public class AuthException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /**
     * Default constructor
     */
    public AuthException() {
        super();
    }

    /**
     * Constructor with message
     *
     * @param message message of exception
     */
    public AuthException(String message) {
        super(message);
    }

    /**
     * Constructor with message and cause
     *
     * @param message message of exception
     * @param cause cause of exception
     */
    public AuthException(String message, Throwable cause) {
        super(message, cause);
    }
}
