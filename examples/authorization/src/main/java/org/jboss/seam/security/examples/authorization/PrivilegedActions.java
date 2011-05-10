package org.jboss.seam.security.examples.authorization;

import javax.enterprise.inject.Model;
import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;
import javax.inject.Inject;

import org.jboss.seam.security.annotations.LoggedIn;
import org.jboss.seam.security.examples.authorization.annotations.Admin;
import org.jboss.seam.security.examples.authorization.annotations.Foo;
import org.jboss.seam.security.examples.authorization.annotations.User;

/**
 * @author Shane Bryzak
 */
public
@Model
class PrivilegedActions {
    @Inject
    FacesContext facesContext;

    @Admin
    public void doSomethingRestricted() {
        facesContext.addMessage(null, new FacesMessage("doSomethingRestricted() invoked"));
    }

    @Foo(bar = "abc", zzz = "nonbindingvalue")
    public void doFooAbc() {
        facesContext.addMessage(null, new FacesMessage("doFooAbc() invoked"));
    }

    @Foo(bar = "def")
    public void doFooDef() {
        facesContext.addMessage(null, new FacesMessage("doFooDef() invoked"));
    }

    @LoggedIn
    public void doLoggedIn() {
        facesContext.addMessage(null, new FacesMessage("doLoggedIn() invoked"));
    }

    @User
    public void doUserAction() {
        facesContext.addMessage(null, new FacesMessage("doUserAction() invoked"));
    }
}
