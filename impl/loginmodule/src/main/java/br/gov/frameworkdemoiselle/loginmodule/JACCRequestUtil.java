package br.gov.frameworkdemoiselle.loginmodule;

import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.servlet.http.HttpServletRequest;

public class JACCRequestUtil {

    public HttpServletRequest getRequest() {
        HttpServletRequest request = null;

        try {
            request = (HttpServletRequest) PolicyContext.getContext("javax.servlet.http.HttpServletRequest");
            PolicyContext.getContextID();
        } catch (PolicyContextException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return request;
    }
}
