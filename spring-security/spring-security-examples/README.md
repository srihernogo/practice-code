## 01-Form-Based-Auth

- Added **Spring Security Dependency**

  - After adding the Spring Security Dependency, when the application is started and hit one of the APIs, the application redirects to the [login](http://localhost:8080/login) page.
  - The default username is **_user_**
  - The default **_password_** is **_generated_** in the application console during the startup of the application.
  - [Logout](http://localhost:8080/logout) page is available as well.
  - This is known as **Form Based Authentication**.

## 02-Basic-Auth

- **Basic Authentication**

  - Authorization: **Base64** Username and Password
  - **HTTPS** Recommended
  - **Simple** and **Fast**
  - **Can't Logout**

- Implemented **Basic Authentication**
  - Added the configuration in _SecurityConfig.java_ file.
  - After this, when the application starts, instead of Form Based Authentication, a pop up window appears and it prompts to enter the Username and Password.
  - This is known as **Basic Auth** from a Web Browser.
  - There's _NO LOGOUT PAGE_! The Username and Password is sent on every single request.
  - Hitting the API from Postman.
    - Select the _request method_ and enter the _URL_.
    - In _Authorization Tab_, select _Basic Auth_ and enter the Username and Password.
    - The Password is _Base64 encoded_.
    - Hit the API!
  * Some useful links
    - [Baeldung - Basic Authentication](https://www.baeldung.com/spring-security-basic-authentication)

## 03-Ant-Matchers

- Implemented **Ant Matchers**
  - Added _index.html_ with a h1 tag in src/main/resources/static.
  - Before adding this, when we try to hit the API after giving Username and Password at 8080 instead of 8080/abc, we get White label error page as there's no endpoint at 8080. But now, the _index.html_ is displayed at http://localhost:8080/.
  - **_To overcome this_**, we have added `antMatchers("/", "index", "/css/*", "/js/*")` in SecurityConfig so that for these URLs the **_Basic Authentication is not required_**.
  - Now, **_Username and Password is not required_** for the URLs specified in **_antMatchers_**!

## 04-Application-Users

- Added **Application Users**
  - In the default Username and Password provided by Spring Security, the **_Username is constant_**. But the **_Password is generated every time_**.
  - But in **_real world_**, the credentials are stored in a Database. Once the Password is set, **_it remains same_** until it is changed.
  - Things needed to access an application in a **_real world scenario_** ?
    - Username
    - Password (_Must be encoded_)
    - Role/s (_ROLE_NAME_)
    - Authorities / Permissions
    - and more...

## 05-Role-Based-Authentication

- **Roles and Permissions**

  - For all the users of the application, we define a _Role_.
  - The Role is just a high level view.
  - _Authorities / Permissions_ are given to the Roles.
  - _Multiple Roles_ can be assigned to a User.
  - Defined **_Roles and Permissions_** inside Security Package.
  - Then, added these Roles to the Users.
  - This is known as **_Role Based Authentication_**.

  - **Disabling CSRF**

  - Created _Management API_.
  - Added a _User_ with _ADMINTRAINEE_ Role.
  - Now, when we hit any of the Management APIs, only _GET APIs_ work.
  - _PUT, POST, DELETE and other APIs_ aren't working.
  - This is because **_Spring Security by default protects_** the application.

## 06-Permission-Based-Authentication

- **Permission Based Authentication**

  - We have _Permissions_ in Security Package.
  - _Permissions_ are given to the _Roles_.
  - _Roles_ are assigned to the _Users_.
  - Permission Based Authentication can be implemented in **_2 ways_**
    - Using **_antMatchers()_**
    - Using **_Annotations_**

- **Using antMatchers() - By adding Authorities to Users**

  - Wrote a method **_getGrantedAuthorities()_** in _UserRoles_.
  - This is to specify the _Authorities_ to the _Roles_.
  - In the SecurityConfig, instead of `.roles(ADMIN.name())` we can use `.authorities(ADMIN.getGrantedAuthorities())`
  - By doing this, **_along with the Roles, the Permissions are also defined_** to the User.
  - After this, the **_antMatchers()_** are added with the **_URLs and the Permissions_**.
  - Now the Management APIs are accessible **_according to the Permissions_**.
  - This is known as **_Permission Based Authentication_**.

> **_The ORDER of antMatchers() DOES MATTER_**

- **Using Annotations - @PreAuthorize**
  - @PreAuthorize takes a String.
    - `hasRole('ROLE_')`
    - `hasAnyRole('ROLE_')`
    - `hasAuthority('permission')`
    - `hasAnyAuthority('permission')`

## 07-Understanding-CSRF

- **Understanding CSRF - _Cross Site Request Forgery_**

  > **_When to use CSRF Protection ?_**

  - It is **_recommended_** to use CSRF protection for any request that could be **_processed by a browser_** by normal users. If you are only creating a **_service_** that is used by **_non-browser clients_**, you will likely want to **_disable CSRF_** protection.
  - Hence **_CSRF is disabled_** in the code as it is a **_Service_**.
    > [CSRF - Cross Site Request Forgery - Spring Docs](https://docs.spring.io/spring-security/site/docs/5.0.x/reference/html/csrf.html) > [Baeldung - A Guide to CSRF Protection in Spring Security](https://www.baeldung.com/spring-security-csrf)

- **CSRF Token**

  - To **_generate_** the CSRF Token, we comment / delete the `csrf().disable()` so that the **_CSRF is enabled_** now.
  - Run the application.
  - In **_Postman_** (From the icon next to the _Settings_), install **_Interceptor Bridge_**.
  - After this, from the same page, click a link to install **_Postman Interceptor_**.
  - This will redirect to the browser and prompt to install the **_Postman Interceptor Extension_** to the browser.
  - Now, back to the Interceptor Bridge in Postman, we can see **_INTERCEPTOR CONNECTED_**.
  - Now the Postman Interceptor installation is **_successful_**.

- **Generating CSRF Token and Hitting the APIs with CSRF Enabled**
  - Refer **_SecurityConfig.java_** for all the **_explanation!!_**
  - Some useful links about **_CSRF Token_**
    - [CookieCsrfTokenRepository.withHttpOnlyFalse()](https://stackoverflow.com/questions/62648098/what-does-cookie-csrftokenrepository-withhttponlyfalse-do-and-when-to-use-it)
    - [CookieCsrfTokenRepository](https://docs.spring.io/spring-security/site/docs/4.2.15.RELEASE/apidocs/org/springframework/security/web/csrf/CookieCsrfTokenRepository.html)
    - [Protection Against Exploits](https://docs.spring.io/spring-security/site/docs/5.2.x/reference/html/protection-against-exploits.html)

## 08-Form-Based-Authentication

- **Form Based Authentication**

  - **_Username_** and **_Password_**
  - **_Standard_** in most websites
  - **_Forms_** (Full Control)
  - **_Can Logout_**
  - **_HTTPS_** Recommended

  * Some useful links **_Form Based Authentication_**

    - [Baeldung](https://www.baeldung.com/spring-security-login)
    - [Javatpoint](https://www.javatpoint.com/spring-security-form-based-authentication)
    - [docs.spring.io](https://docs.spring.io/spring-security/site/docs/4.2.20.RELEASE/guides/html5/form-javaconfig.html)
    - [Howtodoinjava](https://howtodoinjava.com/spring-security/login-form-based-spring-3-security-example/)
    - [Codejava.net](https://www.codejava.net/frameworks/spring-boot/form-authentication-with-jdbc-and-mysql)
    - [Dzone.com](https://dzone.com/articles/spring-security-form-based-authentication)

  * **_How it works ?_**
    - **_Client_** sends **_POST_** Request with **_Username_** and **_Password_** to the **_Server_**.
    - Server **_validates_** and sends **_OK_**.
    - Also, the Server **_sends_** a **_Cookie SESSIONID_** to the **_Client_**.
    - The **_next time_**, the Client sends the **_Request along with SESSIONID_** to the **_Server_**.
    - Server **_validates SESSIONID_** and sends **_Success Response_**.

- **Enable Form Based Authentication**

  - Enabled by `http.formLogin()` in SecurityConfig.java
  - Now, we get the **_Login page_** which we get initially when the **_Spring Security Dependency_** was added to the application.
  - As mentioned in the above (How it works ?) section, we **_enter_** the Username and Password in the Login page.
  - The **_Spring Security validates_** the credentials and sends **_OK_**.
  - Also, it **_sends a Cookie SESSIONID_**.
  - To **_view_** that, on the **_Login page_**, \*Right Click -> Inspect -> Go to **Application** -> **Cookies** -> Select the URL which we hit -> Cookie Name - **JSESSIONID**, Session ID Value will be in the **Value\***.
  - The Cookie SESSIONID is **_valid_** for **_30 Minutes_**.

  * **_Cookie SESSIONID_**

    - The **_Session ID_** is stored in an **_In-Memory Database_**.
    - But in **_real world_**, the best practice is to store the Sessions in a **_Real Database_** such as
      - _PostgreSQL_
      - _Redis etc._

  * **_Some Useful Links_**
    - [Basic Auth and Form Based Auth in same REST API](https://stackoverflow.com/questions/33739359/combining-basic-authentication-and-form-login-for-the-same-rest-api)
    - [Basic Auth and Form Based Auth with Spring Security](https://stackoverflow.com/questions/18729752/basic-and-form-based-authentication-with-spring-security-javaconfig)
    - [Form Based Authentication](https://www.javatpoint.com/spring-security-form-based-authentication)

- **_Custom Login Page_**

  - A Custom Login page can be created and **_can be replaced with the existing default Login page_**.
  - Refer **_SecurityConfig.java_** for the **_code_**.
  - Also, I have added **_Thymeleaf Dependency_** from Spring Boot.
  - Thymeleaf is a **_Templating Engine_** which allows to do many things in regards to **_Html Files_**.
  - After adding the dependency, in src/main/resources, create a folder - **_templates_**.
  - Inside templates, create a file - **_login.html_**
  - And added a **_Controller_** to view Custom Login Page.
  - In login.html, the **_code_** for Custom Login Page **_is taken from the Default Login Page_**.
    > _In the Default Login Page -> Inspect -> Elements -> Right Click on 1st Html Tag and Copy -> Copy Element and paste it in login.html file_.
  - Now, when we hit the **_Login Page Controller_**, we get the Login Page from **_login.html file_**.

  * **_Some useful Links for Thymeleaf_**
    - [Thymeleaf](https://www.thymeleaf.org/)
    - [Baeldung](https://www.baeldung.com/spring-boot-crud-thymeleaf)
    - [TutorialsPoint](https://www.tutorialspoint.com/spring_boot/spring_boot_thymeleaf.htm)
    - [Javatpoint](https://www.javatpoint.com/spring-boot-thymeleaf-view)

- **Redirect After Success Login**

  - When we hit at **_8080_**, it by default redirects to **_index.html_** that is in the _src/main/resources/static_ folder.
  - Now, we **_change it_** to redirect to another page.
  - Refer **_SecurityConfig.java_** for the **_code_**.

- **Remember Me**

  - Usually the **_Cookie SESSIONID_** expires after **_30 Minutes_**.
  - Spring Security offers the **_ability to extend the expiration time_** by using the Remember Me option!
  - Refer **_SecurityConfig.java_** for the **_code_**.
  - When `rememberMe()` is used, it is **_extended to 2 weeks!_**
  - Added a **_Checkbox_** in login.html for Remember Me.
  - When logging in, _Inspect -> Network -> Click on Login page -> Form Data -> We can observe_ `remember-me: on`
  - A **_cookie_** is sent back after logging in.
  - The **_Cookies_** are **_similar_** to the **_Cookie SessionID_**.
  - In **_real world_**, the Cookies are **_persisted to a real Database_**.
  - But now, **_Spring Security_** uses an **_In-Memory Database_** to store the **_Cookies_**.
  - We can find that in the \*Login Page -> Inspect -> Network -> Click on Login page -> **Cookies\***
  - The Cookie has the following:
    - _Username_
    - _Expiration Time_
    - _md5 hash of the above 2 values._
  - **_Customizing_** Cookie Expiration Time - Refer **_SecurityConfig.java_** for the **_code_**.

- **Logout**

  - _Set Request Method for Logout URL_ [_(Best Practice)_](https://docs.spring.io/spring-security/site/docs/4.2.20.RELEASE/apidocs/org/springframework/security/config/annotation/web/configurers/LogoutConfigurer.html#logoutUrl-java.lang.String-)
  - _Set Logout URL_
  - _Clear Authentication_
  - _Invalidate Http Session_
  - _Delete Cookies_
  - _Set the path to be redirected after Logout_

- **Logout Button**

  - In courses.html, added a Logout Button which redirects to /logout.
  - The code for Logout Button is taken from the login.html file and modified a bit.

- **Password, Username & Remember-Me Parameters**
  - Refer **_SecurityConfig.java_** for the **_code_**.

## 09-DB-Authentication

- **DB Authentication**
  - Created a **_new Package_** called **_databaseAuthentication_**.
  - Created a Class called _ApplicationUser_ which **_implements_** _UserDetails Interface_.
  - **_Added_** unimplemented methods.
  - Then **_customized_** the class.
  - Created _ApplicationUserDAO, ApplicationUserService & FakeApplicationUserDAOService_.
  - Added `daoAuthenticationProvider()` & `configure(AuthenticationManagerBuilder auth)` in **_SecurityConfig.java_**.
  - Commented the `userDetailsService()` method so that the **_Users_** are **_fetched_** from the **_Database Authentication_** implementation.

## 10-JWT-JSON-Web-Token

- **JSON WEB TOKEN - JWT**

  - **_Pros_**
    - _Fast_
    - _Stateless_
      - It **_doesn't need to have a database!_**
      - It **_doesn't need to store the session_** of the current user!
      - **_Everything is embedded_** inside the token!
    - _Used across many services_
  - **_Cons_**
    - _Compromised secret key_
      - If the secret key is compromised, it leads to a trouble.
    - _No visibility to logged in users_
      - Unlike Form Based Authentication etc., we don't know when the user logs in, logs out, no history etc.
    - _Token can be stolen_
      - If the token is stolen, a hacker can pretend to be a real user in the system.
  - Some useful links

    - [_https://jwt.io/_](https://jwt.io/)
    - [_JWT Debugger Tool_](https://jwt.io/#debugger-io)
    - [_Java Jwt GitHub_](https://github.com/jwtk/jjwt)
    - [_https://flaviocopes.com/jwt/_](https://flaviocopes.com/jwt/)
    - [_https://medium.com/_](https://medium.com/@sureshdsk/how-json-web-token-jwt-authentication-works-585c4f076033)

  - **How it works ?**

    - **_Client_** sends **_credentials_** (Username and Password) to the **_Server_**.
    - **_Server validates_** the credentials and **_Creates and Signs the Token_**.
    - **_Server_** sends the **_Token_** to the **_Client_**.
    - From **_next time_**, the **_Client_** sends only the **_Token_** in **_each requests_**.
    - **_Server validates_** the Token.

  - **What a JWT Token has ?**

    - JWT Token has **_3 parts_**
      - _Header_
      - _Payload_
      - _Verify Signature_

  - **Jwt Dependencies**

    - _The dependencies are taken from_ [**_Java Jwt Github_**](https://github.com/jwtk/jjwt)

  - **Code changes** - Created a package called **_jwt_**. - Refer **_jwt_** package for the code. - **_Commented_** the existing configure(HttpSecurity http) method in SecurityConfig.java and **_implemented JWT Authentication in a new method_** to avoid confusion. - To use JWT Authentication, this method can be used. - To use other Spring Security Features like Basic Authentication, Form Based Authentication etc., another configure(HttpSecurity http) method can be uncommented and used.

  - **_Request Filters_** - **_Request_** **->** _Filter1_ **->** _Filter2_ **->** _Filter3_ **->** _FilterN_ **->** **_API_** - **_Request Filters_** are some **_classes_** that perform **_some validations_** before reaching the **_final destination (API)_**. - In our application, **_JwtUsernameAndPasswordAuthenticationFilter.java_** is one of the filters. - We can have **_as many filters as we want_**. - The **_Order_** of these Filters is **_NOT guaranteed_**. - When the **_1st Filter is executed_**, it has to pass on the **_Request and Response_** to the **_next Filter_**.

  > NOTE:
  >
  > - Make sure the **_Expiration Time_** of the Token as not too long. Keep it like **_10 Days or 7 Days or even less_**.
  > - This can **_let a User authenticate_** to your system **_as much as possible_**.
  > - A **_User_** can **_request_** for **_as many Tokens_** as he wants. Currently (With context to this application) the **_best way to fix_** this is to **_store the Tokens and User Information_** in a **_Real Database_**.
  > - So when the **_User requests for another Token, we can invalidate the pre-existing ones_**.
