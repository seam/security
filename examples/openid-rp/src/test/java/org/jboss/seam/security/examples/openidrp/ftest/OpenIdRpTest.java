package org.jboss.seam.security.examples.openidrp.ftest;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Properties;

import org.jboss.test.selenium.AbstractTestCase;
import org.jboss.test.selenium.locator.IdLocator;
import org.jboss.test.selenium.locator.XpathLocator;
import org.jboss.test.selenium.waiting.selenium.SeleniumCondition;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.jboss.test.selenium.guard.request.RequestTypeGuardFactory.waitHttp;
import static org.jboss.test.selenium.locator.LocatorFactory.id;
import static org.jboss.test.selenium.locator.LocatorFactory.xp;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

/**
 * A functional test for the openid-rp example
 *
 * @author Martin Gencur
 */
public class OpenIdRpTest extends AbstractTestCase {
    private static Properties properties = new Properties();
    private static boolean propertiesLoaded = false;
    private static String PROPERTY_FILE = "ftest.properties";
    private static final int checkInterval = 1000;
    private static final int modelTimeout = 30000;
    protected XpathLocator LOGIN_LINK = xp("//a[contains(text(),'Login')]");
    protected XpathLocator LOGOUT_LINK = xp("//a[contains(text(),'Logout')]");
    protected XpathLocator LAST_CELL = xp("//div[@class='content']/table/tbody/tr[3]/td[2]");
    protected XpathLocator MYOPENID_RADIO = xp("//input[@type='radio'][@value='myopenid']");
    protected XpathLocator GOOGLE_RADIO = xp("//input[@type='radio'][@value='google']");
    protected XpathLocator YAHOO_RADIO = xp("//input[@type='radio'][@value='yahoo']");
    protected XpathLocator CUSTOM_RADIO = xp("//input[@type='radio'][@value='custom']");
    protected XpathLocator ADDRESS_FIELD = xp("//input[@type='text']");
    protected XpathLocator SUBMIT_BUTTON = xp("//input[@value='login']");
    protected IdLocator MYOPENID_USERNAME = id("identity");
    protected IdLocator MYOPENID_PASSWORD = id("password");
    protected IdLocator MYOPENID_SIGN_IN = id("signin_button");
    protected IdLocator GOOGLE_USERNAME = id("Email");
    protected IdLocator GOOGLE_PASSWORD = id("Passwd");
    protected IdLocator GOOGLE_SIGN_IN = id("signIn");
    protected IdLocator GOOGLE_APPROVAL = id("approve_button");
    protected IdLocator YAHOO_USERNAME = id("username");
    protected IdLocator YAHOO_PASSWORD = id("passwd");
    protected IdLocator YAHOO_SIGN_IN = id(".save");
    protected IdLocator YAHOO_APPROVAL = id("agree");

    @BeforeMethod
    public void openStartUrl() throws MalformedURLException {
        selenium.setSpeed(100);
        selenium.open(new URL(contextPath.toString()));
    }

    @Test(dependsOnMethods = {"testGoogle"})
    public void testMyOpenID() {
        waitHttp(selenium).click(LOGIN_LINK);
        selenium.check(MYOPENID_RADIO);
        selenium.click(SUBMIT_BUTTON);
        waitModel.interval(checkInterval).timeout(modelTimeout).until(elementPresent.locator(MYOPENID_USERNAME));
        selenium.type(MYOPENID_USERNAME, getProperty("myopenid.username"));
        selenium.type(MYOPENID_PASSWORD, getProperty("myopenid.password"));
        selenium.click(MYOPENID_SIGN_IN);
        checkMyOpenIdSignedIn();
    }

    @Test
    public void testGoogle() {
        waitHttp(selenium).click(LOGIN_LINK);
        selenium.check(GOOGLE_RADIO);
        selenium.click(SUBMIT_BUTTON);
        waitModel.interval(checkInterval).timeout(modelTimeout).until(elementPresent.locator(GOOGLE_USERNAME));
        selenium.type(GOOGLE_USERNAME, getProperty("google.username"));
        selenium.type(GOOGLE_PASSWORD, getProperty("google.password"));
        waitHttp(selenium).click(GOOGLE_SIGN_IN);
        if (selenium.isElementPresent(GOOGLE_APPROVAL)) {
            waitHttp(selenium).click(GOOGLE_APPROVAL);
        }
        waitModel.interval(checkInterval).timeout(modelTimeout / 2).until(elementPresent.locator(LAST_CELL));
        assertTrue(selenium.isTextPresent("Verified User Identifier"), "User should be verified now!");
        assertTrue(selenium.isTextPresent("OpenID Provider"), "OpendID Provider info should be displayed");
        assertTrue(selenium.isTextPresent("https://www.google.com/accounts/"), "OpendID Provider name should be displayed");
        waitHttp(selenium).click(LOGOUT_LINK);
        assertFalse(selenium.isTextPresent("https://www.google.com/accounts/"), "User should be logged out now");
    }

    @Test
    public void testYahoo() {
        waitHttp(selenium).click(LOGIN_LINK);
        selenium.check(YAHOO_RADIO);
        selenium.click(SUBMIT_BUTTON);
        waitModel.interval(checkInterval).timeout(modelTimeout).until(elementPresent.locator(YAHOO_USERNAME));
        selenium.type(YAHOO_USERNAME, getProperty("yahoo.username"));
        selenium.type(YAHOO_PASSWORD, getProperty("yahoo.password"));
        waitHttp(selenium).click(YAHOO_SIGN_IN);
        if (selenium.isElementPresent(YAHOO_APPROVAL)) {
            waitHttp(selenium).click(YAHOO_APPROVAL);
        }
        waitModel.interval(checkInterval).timeout(modelTimeout / 2).until(elementPresent.locator(LAST_CELL));
        assertTrue(selenium.isTextPresent("Verified User Identifier"), "User should be verified now!");
        assertTrue(selenium.isTextPresent("OpenID Provider"), "OpendID Provider info should be displayed");
        assertTrue(selenium.isTextPresent("https://open.login.yahooapis.com/openid/op/auth"), "OpendID Provider name should be displayed");
        waitHttp(selenium).click(LOGOUT_LINK);
        assertFalse(selenium.isTextPresent("https://open.login.yahooapis.com/openid/op/auth"), "User should be logged out now");
    }

    @Test(dependsOnMethods = {"testMyOpenID"})
    public void testCustom() {
        waitHttp(selenium).click(LOGIN_LINK);
        selenium.check(CUSTOM_RADIO);
        selenium.type(ADDRESS_FIELD, "https://www.myopenid.com/");
        selenium.click(SUBMIT_BUTTON);
        checkMyOpenIdSignedIn();
    }

    public void checkMyOpenIdSignedIn() {
        waitModel.interval(checkInterval).timeout(modelTimeout / 2).until(new SeleniumCondition() {
            @Override
            public boolean isTrue() {
                return selenium.isTextPresent("Email") && selenium.isElementPresent(LAST_CELL);
            }
        });
        assertTrue(selenium.isTextPresent("Verified User Identifier"), "User should be verified now!");
        assertTrue(selenium.isTextPresent("https://" + getProperty("myopenid.username") + "/"), "The user identifier should be displayed");
        assertTrue(selenium.isTextPresent("OpenID Provider"), "OpendID Provider info should be displayed");
        assertTrue(selenium.isTextPresent("https://www.myopenid.com/server"), "OpendID Provider name should be displayed");
        waitHttp(selenium).click(LOGOUT_LINK);
        assertFalse(selenium.isTextPresent("https://www.myopenid.com/server"), "User should be logged out now");
    }

    public String getProperty(String key) {
        if (!propertiesLoaded) {
            try {
                properties.load(this.getClass().getClassLoader().getResourceAsStream(PROPERTY_FILE));
                propertiesLoaded = true;
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return properties.getProperty(key, "Property not found: " + key);
    }
}
