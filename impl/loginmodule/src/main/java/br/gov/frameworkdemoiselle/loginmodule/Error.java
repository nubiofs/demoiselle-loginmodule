package br.gov.frameworkdemoiselle.loginmodule;

import java.security.Principal;
import java.util.Collection;
import java.util.HashSet;

public class Error implements Principal {

    private Collection<String> errors;

    public void addError(String error) {
        if (this.errors == null) {
            this.errors = new HashSet<String>();
        }
        this.errors.add(error);
    }

    public void addErrors(Collection<String> errors) {
        for (String error : errors) {
            addError(error);
        }
    }

    public Collection<String> getErrors() {
        return this.errors;
    }

    public String getName() {
        return "ERROR";
    }
}
