package org.jboss.seam.security.examples.simple.ftest;

import static org.testng.Assert.assertTrue;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import java.net.MalformedURLException;
import java.net.URL;
import org.jboss.test.selenium.AbstractTestCase;
import org.jboss.test.selenium.locator.IdLocator;
import org.jboss.test.selenium.locator.XpathLocator;
import static org.jboss.test.selenium.locator.LocatorFactory.id;
import static org.jboss.test.selenium.locator.LocatorFactory.xp;
import static org.jboss.test.selenium.guard.request.RequestTypeGuardFactory.waitHttp;

/**
 * A functional test for a Simple example
 * 
 * @author Martin Gencur
 * 
 */
public class SimpleTest extends AbstractTestCase
{
   protected String MAIN_PAGE = "/home.jsf";
   protected IdLocator USERNAME_INPUT = id("loginForm:name");
   protected IdLocator PASSWORD_INPUT = id("loginForm:password");
   protected IdLocator LOGIN_BUTTON = id("loginForm:login");
   protected XpathLocator LOGOUT_BUTTON = xp("//input[contains(@id,'logout')]");

   @BeforeMethod
   public void openStartUrl() throws MalformedURLException
   {
      selenium.setSpeed(100);
      selenium.open(new URL(contextPath.toString() + MAIN_PAGE));
   }

   @Test
   public void testLoginLogout()
   {
      selenium.type(USERNAME_INPUT, "demo");
      selenium.type(PASSWORD_INPUT, "demo");
      waitHttp(selenium).click(LOGIN_BUTTON);
      assertTrue(selenium.isTextPresent("Currently logged in as: demo"), "User should be logged in now.");
      waitHttp(selenium).click(LOGOUT_BUTTON);
      assertTrue(selenium.isElementPresent(LOGIN_BUTTON), "User should NOT be logged in.");
      assertTrue(selenium.isTextPresent("Tip: you can login with a username/password of demo/demo."), 
         "User should NOT be logged in.");
   }
}
