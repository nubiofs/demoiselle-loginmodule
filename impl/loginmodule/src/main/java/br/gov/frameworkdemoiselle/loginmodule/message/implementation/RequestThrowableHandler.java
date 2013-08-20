package br.gov.frameworkdemoiselle.loginmodule.message.implementation;

import javax.security.jacc.PolicyContext;
import javax.servlet.http.HttpServletRequest;

import br.gov.frameworkdemoiselle.loginmodule.AuthException;
import br.gov.frameworkdemoiselle.loginmodule.message.IThrowableHandler;

public class RequestThrowableHandler implements IThrowableHandler {

    public static final String THROWABLE_KEY = "javax.servlet.error.exception";

    public void handle(Throwable throwable) {
        try {
            HttpServletRequest request = (HttpServletRequest) PolicyContext.getContext(HttpServletRequest.class.getName());

            request.setAttribute(THROWABLE_KEY, throwable);
        } catch (Exception e) {
            throw new AuthException("Error: Could not get context " + HttpServletRequest.class.getName() + " in PolicyContext", e);
        }
    }
}
