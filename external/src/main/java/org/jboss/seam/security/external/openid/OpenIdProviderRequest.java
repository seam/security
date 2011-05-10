package org.jboss.seam.security.external.openid;

import java.io.Serializable;
import java.util.List;

import org.jboss.seam.security.external.dialogues.api.DialogueScoped;
import org.jboss.seam.security.external.openid.api.OpenIdRequestedAttribute;
import org.openid4java.message.ParameterList;
import org.openid4java.message.ax.FetchRequest;

/**
 * @author Marcel Kolsteren
 */
@DialogueScoped
public class OpenIdProviderRequest implements Serializable {
    private static final long serialVersionUID = -6701058408595984106L;

    private ParameterList parameterList;

    private String claimedIdentifier;

    private List<OpenIdRequestedAttribute> requestedAttributes;

    private FetchRequest fetchRequest;

    private String userName;

    public ParameterList getParameterList() {
        return parameterList;
    }

    public void setParameterList(ParameterList parameterList) {
        this.parameterList = parameterList;
    }

    public String getClaimedIdentifier() {
        return claimedIdentifier;
    }

    public void setClaimedIdentifier(String claimedIdentifier) {
        this.claimedIdentifier = claimedIdentifier;
    }

    public List<OpenIdRequestedAttribute> getRequestedAttributes() {
        return requestedAttributes;
    }

    public void setRequestedAttributes(List<OpenIdRequestedAttribute> requestedAttributes) {
        this.requestedAttributes = requestedAttributes;
    }

    public FetchRequest getFetchRequest() {
        return fetchRequest;
    }

    public void setFetchRequest(FetchRequest fetchRequest) {
        this.fetchRequest = fetchRequest;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }
}
