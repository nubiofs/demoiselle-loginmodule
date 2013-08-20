package br.gov.frameworkdemoiselle.loginmodule;

import java.io.Serializable;
import java.security.Principal;

public class Role implements Principal, Serializable {

    private static final long serialVersionUID = 1L;
    private String name;

    public Role(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }
}
