package org.jboss.seam.security.examples.idmconsole.ftest;

import static org.testng.Assert.assertTrue;
import static org.testng.Assert.assertFalse;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import java.net.MalformedURLException;
import java.net.URL;
import org.jboss.test.selenium.AbstractTestCase;
import org.jboss.test.selenium.locator.IdLocator;
import org.jboss.test.selenium.locator.XpathLocator;
import org.jboss.test.selenium.locator.option.OptionLabelLocator;
import org.jboss.test.selenium.locator.option.OptionLocator;
import static org.jboss.test.selenium.locator.LocatorFactory.id;
import static org.jboss.test.selenium.locator.LocatorFactory.xp;
import static org.jboss.test.selenium.guard.request.RequestTypeGuardFactory.waitHttp;
import static org.jboss.test.selenium.locator.option.OptionLocatorFactory.optionLabel;


/**
 * A functional test for an IdmConsole example
 * 
 * @author Martin Gencur
 * 
 */
public class IdmConsoleTest extends AbstractTestCase
{
   protected String homeUrl = "/home.jsf";
   protected IdLocator LOGIN_USERNAME = id("loginForm:name");
   protected IdLocator LOGIN_PASSWORD = id("loginForm:password");
   protected IdLocator LOGIN = id("loginForm:login");
   protected XpathLocator LOGOUT = xp("//a[contains(text(),'Log out')]");
   protected XpathLocator CHANGE_PASSWORD = xp("//a[contains(text(),'Change password')]");
   
   protected XpathLocator MANAGE_USERS = xp("//a[contains(text(),'Manage users')]");
   protected XpathLocator MANAGE_GROUPS = xp("//a[contains(text(),'Manage groups')]");
   protected XpathLocator MANAGE_ROLES = xp("//a[contains(text(),'Manage role types')]");
   
   protected XpathLocator CREATE_USER = xp("//a[contains(text(),'Create New User')]");
   protected IdLocator USER_USERNAME = id("user:username");
   protected String userName = "martin";
   protected IdLocator USER_PASSWORD = id("user:password");
   protected IdLocator USER_CONFIRM = id("user:confirm");
   protected IdLocator USER_ENABLED = id("user:enabled");
   protected IdLocator USER_ADD_ROLE = id("user:addRole");
   protected IdLocator USER_SAVE = id("user:save");
   protected IdLocator USER_CANCEL = id("user:cancel");
   protected XpathLocator USER_ADDED = xp("//tbody/tr/td[contains(text(),'"+ userName +"')]");
   
   /* Edit link next to the newly added user */
   protected XpathLocator USER_EDIT = xp("//tbody/tr[4]/td[3]/a[contains(text(),'Edit')]"); 
   /* Delete link next to the newly added user */
   protected XpathLocator USER_DELETE = xp("//tbody/tr[4]/td[3]/a[contains(text(),'Delete')]");
   protected IdLocator ROLE_TYPE = id("role:roleType");
   protected IdLocator ROLE_GROUP = id("role:roleGroup");
   protected OptionLocator<OptionLabelLocator> ADMIN_ROLE = optionLabel("admin");
   protected OptionLocator<OptionLabelLocator> HEAD_GROUP = optionLabel("Head Office");
   protected IdLocator ROLE_ADD = id("role:add");
   
   protected XpathLocator CREATE_GROUP = xp("//a[contains(text(),'Create new group')]");
   protected IdLocator GROUP_NAME = id("group:groupname");
   protected IdLocator GROUP_SAVE = id("group:save");
   protected String groupName = "PittsburghPenguins";
   protected XpathLocator GROUP_ADDED = xp("//tbody/tr/td[contains(text(),'"+ groupName +"')]");
   /* Delete link next to the newly added group */
   protected XpathLocator GROUP_DELETE = xp("//tbody/tr[2]/td[2]/a[contains(text(),'Delete')]");
   
   protected XpathLocator CREATE_ROLE = xp("//a[contains(text(),'Create new role')]");
   protected IdLocator ROLE_NAME = id("role:roleType");
   protected IdLocator ROLE_SAVE = id("role:add");
   protected String roleName = "accountant";
   protected XpathLocator ROLE_ADDED = xp("//tbody/tr/td[contains(text(),'"+ roleName +"')]");
   /* Delete link next to the newly added role */
   protected XpathLocator ROLE_DELETE = xp("//tbody/tr[3]/td[2]/a[contains(text(),'Delete')]");
   
   protected IdLocator OLD_PASSWORD = id("changepassword:oldPassword");
   protected IdLocator NEW_PASSWORD = id("changepassword:newPassword");
   protected IdLocator CONFIRM_PASSWORD = id("changepassword:confirmPassword");
   protected IdLocator PASSWORD_SAVE = id("changepassword:save");
   
   protected String defaultUser = "demo";
   protected String defaultPassword = "demo";
   protected String newPassword = "newpassword";
   
   @BeforeMethod
   public void setup() throws MalformedURLException
   {
      selenium.open(new URL(contextPath.toString() + homeUrl));
      waitModel.until(elementPresent.locator(LOGIN_PASSWORD));
      login();
   }
   
   @AfterMethod
   public void tearDown()
   {
      logout();
   }

   @Test
   public void testCreateGroup()
   {
      deleteGroup(); //in case the group already exists
      waitHttp(selenium).click(MANAGE_GROUPS);
      waitHttp(selenium).click(CREATE_GROUP);
      selenium.type(GROUP_NAME, groupName);
      waitHttp(selenium).click(GROUP_SAVE);
      assertTrue(selenium.isElementPresent(GROUP_ADDED), "Group should be added now");
   }
   
   @Test(dependsOnMethods={"testCreateGroup"})
   public void testDeleteGroup()
   {
      deleteGroup();
      assertFalse(selenium.isElementPresent(GROUP_ADDED), "Group should be removed now");
   }

   private void deleteGroup()
   {
      waitHttp(selenium).click(MANAGE_GROUPS);
      if (selenium.isElementPresent(GROUP_DELETE))
      {
         selenium.chooseOkOnNextConfirmation();
         waitHttp(selenium).click(GROUP_DELETE);
         selenium.getConfirmation();
      }
   }
   
   @Test(dependsOnMethods={"testDeleteGroup"})
   public void testCreateUser()
   {
      deleteUser(); //in case the user already exists
      waitHttp(selenium).click(MANAGE_USERS);
      waitHttp(selenium).click(CREATE_USER);
      selenium.type(USER_USERNAME, userName);
      selenium.type(USER_PASSWORD, "mypassword");
      selenium.type(USER_CONFIRM, "mypassword");
      selenium.check(USER_ENABLED);
      waitHttp(selenium).click(USER_SAVE);
      assertTrue(selenium.isElementPresent(USER_ADDED), "User should be added now");
   }

   @Test(dependsOnMethods={"testCreateUser"})
   public void testAddNewRole()
   {
      waitHttp(selenium).click(MANAGE_USERS);
      waitHttp(selenium).click(USER_EDIT);
      waitHttp(selenium).click(USER_ADD_ROLE);
      selenium.select(ROLE_TYPE, ADMIN_ROLE);
      selenium.select(ROLE_GROUP, HEAD_GROUP);
      waitHttp(selenium).click(ROLE_ADD);
      assertTrue(selenium.isTextPresent("admin in group Head Office"), "'admin' role should be added now");
   }
   
   @Test(dependsOnMethods={"testAddNewRole"})
   public void testDeleteUser()
   {
      deleteUser();
      assertFalse(selenium.isElementPresent(USER_EDIT), "User should be removed now");
   }

   private void deleteUser()
   {
      waitHttp(selenium).click(MANAGE_USERS);
      if (selenium.isElementPresent(USER_DELETE))
      {
         selenium.chooseOkOnNextConfirmation();
         waitHttp(selenium).click(USER_DELETE);
         selenium.getConfirmation();
      }
   }
   
   @Test
   public void testCreateRole()
   {
      deleteRole();
      waitHttp(selenium).click(MANAGE_ROLES);
      waitHttp(selenium).click(CREATE_ROLE);
      selenium.type(ROLE_NAME, roleName);
      waitHttp(selenium).click(ROLE_SAVE);
      assertTrue(selenium.isElementPresent(ROLE_ADDED), "Role should be added now");
   }
   
   @Test(dependsOnMethods={"testCreateRole"})
   public void testDeleteRole()
   {
      deleteRole(); //in case the role already exists
      assertFalse(selenium.isElementPresent(ROLE_ADDED), "Role should be removed now");
   }

   private void deleteRole()
   {
      waitHttp(selenium).click(MANAGE_ROLES);
      if (selenium.isElementPresent(ROLE_DELETE))
      {
         selenium.chooseOkOnNextConfirmation();
         waitHttp(selenium).click(ROLE_DELETE);
         selenium.getConfirmation();
      }
   }
   
   @Test
   public void testChangePassword()
   {
      changePassword(defaultPassword, newPassword);
      logout();
      login(defaultUser, newPassword);
      changePassword(newPassword, defaultPassword); //change the password back to original
   }

   private void changePassword(String defaultPassword, String newPassword)
   {
      waitHttp(selenium).click(CHANGE_PASSWORD);
      selenium.type(OLD_PASSWORD, defaultPassword); 
      selenium.type(NEW_PASSWORD, newPassword);
      selenium.type(CONFIRM_PASSWORD, newPassword); 
      waitHttp(selenium).click(PASSWORD_SAVE);
   }
   
   private void logout()
   {
      waitHttp(selenium).click(LOGOUT);
   }

   private void login()
   {
      login(defaultUser, defaultPassword);
   }
   
   private void login(String userName, String password)
   {
      selenium.type(LOGIN_USERNAME, userName);
      selenium.type(LOGIN_PASSWORD, password);
      waitHttp(selenium).click(LOGIN);
      assertTrue(selenium.isElementPresent(LOGOUT), "Login was not successful");
   }
}
