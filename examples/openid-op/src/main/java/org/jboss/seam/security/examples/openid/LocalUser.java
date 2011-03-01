/*
 * JBoss, Home of Professional Open Source
 * Copyright 2010, Red Hat, Inc., and individual contributors
 * by the @authors tag. See the copyright.txt in the distribution for a
 * full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.jboss.seam.security.examples.openid;

import java.io.Serializable;

import org.picketlink.idm.api.User;

public class LocalUser implements Serializable, User {
    private static final long serialVersionUID = -7096110154986991513L;

    private String userName;

    private String opLocalIdentifier;

    // @Inject
    // private OpenIdProviderApi providerApi;
    //
    // public void localLogin(String userName)
    // {
    // this.userName = userName;
    // }
    //
    // public void logout()
    // {
    // if (isLoggedIn())
    // {
    // userName = null;
    // redirectToViewId("/Index.xhtml");
    // }
    // else
    // {
    // FacesMessage facesMessage = new FacesMessage("Not logged in.");
    // FacesContext.getCurrentInstance().addMessage(null, facesMessage);
    // }
    // }

    // public boolean isLoggedIn()
    // {
    // return userName != null;
    // }

    public String getUserName() {
        return userName;
    }

    public String getOpLocalIdentifier() {
        return opLocalIdentifier;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public void setOpLocalIdentifier(String opLocalIdentifier) {
        this.opLocalIdentifier = opLocalIdentifier;
    }

    @Override
    public String getKey() {
        return userName;
    }

    @Override
    public String getId() {
        return userName;
    }


}
