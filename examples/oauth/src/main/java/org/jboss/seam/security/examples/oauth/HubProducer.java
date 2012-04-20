/**
 * 
 */
package org.jboss.seam.security.examples.oauth;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Produces;

import org.jboss.seam.social.Facebook;
import org.jboss.seam.social.FacebookServicesHub;
import org.jboss.seam.social.LinkedIn;
import org.jboss.seam.social.LinkedInServicesHub;
import org.jboss.seam.social.Twitter;
import org.jboss.seam.social.TwitterServicesHub;
import org.jboss.seam.social.oauth.OAuthApplication;

/**
 * @author Antoine Sabot-Durand
 * 
 */
public class HubProducer {

    @Twitter
    @ApplicationScoped
    @OAuthApplication(apiKey = "FQzlQC49UhvbMZoxUIvHTQ", apiSecret = "VQ5CZHG4qUoAkUUmckPn4iN4yyjBKcORTW0wnok4r1k", callback = "http://localhost:8080/security-oauth/callback.jsf")
    @Produces
    public TwitterServicesHub twitterProducer(TwitterServicesHub service) {
        return service;
    }

    @LinkedIn
    @ApplicationScoped
    @OAuthApplication(apiKey = "ympq1JR_oxeC3qZE4VwiDEr-9Rc9Am0YE1AJwwXJNREfqaF7J6hXfsncu_JFd13W", apiSecret = "RwDk21M6qQeGT_zi2icmZV6tc5VsjRZPm7DWDIVt0Wsqu2eYBXt4Csg-FUbBZIIH", callback = "http://localhost:8080/security-oauth/callback.jsf")
    @Produces
    public LinkedInServicesHub linkedInProducer(LinkedInServicesHub service) {
        return service;
    }

    @Facebook
    @ApplicationScoped
    @OAuthApplication(apiKey = "204631749555557", apiSecret = "5d3132b1448a66d28e5c420b267cd65e", callback = "http://localhost:8080/security-oauth/callback.jsf", scope = "read_stream publish_stream")
    @Produces
    public FacebookServicesHub facebookProducer(FacebookServicesHub service) {
        return service;
    }

}
