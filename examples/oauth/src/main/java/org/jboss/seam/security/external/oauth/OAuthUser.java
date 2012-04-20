/*
 * JBoss, Home of Professional Open Source
 * Copyright 2012, Red Hat Middleware LLC, and individual contributors
 * by the @authors tag. See the copyright.txt in the distribution for a
 * full listing of individual contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jboss.seam.security.external.oauth;

import org.jboss.seam.social.UserProfile;
import org.picketlink.idm.api.User;

/**
 * Represents a user authenticated using OAuth
 * 
 * @author maschmid
 *
 */
public class OAuthUser implements User {
    
    public OAuthUser(String serviceName, UserProfile profile) {
        this.serviceName = serviceName;
        this.profile = profile;
    }
    
    private UserProfile profile;
    private String serviceName;

    @Override
    public String getKey() {
        return getId();
    }

    @Override
    public String getId() {
        return serviceName + "_" + profile.getId();
    }
    
    public UserProfile getUserProfile() {
        return profile;
    } 
    
    public String getServiceName() {
        return serviceName;
    }
    
    /**
     * @return id that is unique to the OAuth service
     */
    public String getOauthId() {
        return profile.getId(); 
    }
}
