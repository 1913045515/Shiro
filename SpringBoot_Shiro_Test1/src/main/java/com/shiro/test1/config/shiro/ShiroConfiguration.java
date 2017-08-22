package com.shiro.test1.config.shiro;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.commons.collections.map.HashedMap;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.cas.CasFilter;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.config.Ini;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.RememberMeManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.SessionListener;
import org.apache.shiro.session.mgt.DefaultSessionManager;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.util.Factory;
import org.apache.shiro.web.config.WebIniSecurityManagerFactory;
import org.apache.shiro.web.filter.authc.FormAuthenticationFilter;
import org.apache.shiro.web.mgt.CookieRememberMeManager;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.apache.shiro.web.session.mgt.ServletContainerSessionManager;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.apache.shiro.cache.ehcache.EhCacheManager;
import org.springframework.web.filter.DelegatingFilterProxy;

import javax.servlet.Filter;

/**
 * Shiro 配置
 * <p>
 * Apache Shiro 核心通过 Filter 来实现，就好像SpringMvc 通过DispachServlet 来主控制一样。
 * 既然是使用 Filter 一般也就能猜到，是通过URL规则来进行过滤和权限校验，所以我们需要定义一系列关于URL的规则和访问权限。
 *
 * @author Angel(QQ:412887952)
 * @version v.0.1
 */
//@Configuration
public class ShiroConfiguration {
//    // CasServerUrlPrefix
//    public static final String casServerUrlPrefix = "https://localhost:8080";
//    // Cas登录页面地址
//    public static final String casLoginUrl = casServerUrlPrefix + "/login";
//    // Cas登出页面地址
//    public static final String casLogoutUrl = casServerUrlPrefix + "/logout";
//    // 当前工程对外提供的服务地址
//    public static final String shiroServerUrlPrefix = "http://localhost:9090/myspringboot";
//    // casFilter UrlPattern
//    public static final String casFilterUrlPattern = "/shiro-cas";
//    // 登录地
//    public static final String loginUrl = casLoginUrl + "?service=" + shiroServerUrlPrefix + casFilterUrlPattern;

    /**
     * ShiroFilterFactoryBean 处理拦截资源文件问题。
     * 注意：单独一个ShiroFilterFactoryBean配置是或报错的，以为在
     * 初始化ShiroFilterFactoryBean的时候需要注入：SecurityManager
     * <p>
     * Filter Chain定义说明
     * 1、一个URL可以配置多个Filter，使用逗号分隔
     * 2、当设置多个过滤器时，全部验证通过，才视为通过
     * 3、部分过滤器可指定参数，如perms，roles
     */
    @Bean(name = "shiroFilter")
    public ShiroFilterFactoryBean shirFilter(SecurityManager securityManager) {
        System.out.println("ShiroConfiguration.shirFilter()");
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
        // 必须设置 SecurityManager
        shiroFilterFactoryBean.setSecurityManager(securityManager);
        Map map = new HashedMap();
//		Map<String, Filter> filters = shiroFilterFactoryBean.getFilters();//获取filters
//		filters.put("authc",formAuthenticationFilter());//将自定义 的FormAuthenticationFilter注入shiroFilter中
//		filters.put("kickout",getKickoutSessionControlFilter());
        map.put("kickout", getKickoutSessionControlFilter());
//        map.put("casFilter",getCasFilter());
//		map.put("user",formAuthenticationFilter());
        shiroFilterFactoryBean.setFilters(map);
        //拦截器.
        Map<String, String> filterChainDefinitionMap = new LinkedHashMap<String, String>();

        //配置退出 过滤器,其中的具体的退出代码Shiro已经替我们实现了

        filterChainDefinitionMap.put("/logout", "logout");

        //<!-- 过滤链定义，从上向下顺序执行，一般将 /**放在最为下边 -->:这是一个坑呢，一不小心代码就不好使了;
        //<!-- authc:所有url都必须认证通过才可以访问; anon:所有url都都可以匿名访问-->
//		filterChainDefinitionMap.put("/index", "kickout,authc");
        filterChainDefinitionMap.put("/out", "user");
        filterChainDefinitionMap.put("/index", "anon");
        filterChainDefinitionMap.put("/**", "kickout,authc");
        // 如果不设置默认会自动寻找Web工程根目录下的"/login.jsp"页面
        shiroFilterFactoryBean.setLoginUrl("/login");
        // 登录成功后要跳转的链接
        shiroFilterFactoryBean.setSuccessUrl("/index");
        //未授权界面;
        shiroFilterFactoryBean.setUnauthorizedUrl("/403");
//        filterChainDefinitionMap.put(casFilterUrlPattern, "casFilter");// shiro集成cas后，首先添加该规则
        shiroFilterFactoryBean.setFilterChainDefinitionMap(filterChainDefinitionMap);
        return shiroFilterFactoryBean;
    }

//    @Bean(name = "myShiroCasRealm")
//    public MyShiroCasRealm myShiroCasRealm() {//EhCacheManager cacheManager
//        MyShiroCasRealm realm = new MyShiroCasRealm();
////        realm.setCacheManager(cacheManager);
//        realm.setCredentialsMatcher(hashedCredentialsMatcher());
//        return realm;
//    }
//
//    /**
//     * 注册DelegatingFilterProxy（Shiro）
//     *
//     * @return
//     * @author SHANHY
//     * @create  2016年1月13日
//     */
//    @Bean
//    public FilterRegistrationBean filterRegistrationBean() {
//        FilterRegistrationBean filterRegistration = new FilterRegistrationBean();
//        filterRegistration.setFilter(new DelegatingFilterProxy("shiroFilter"));
//        //  该值缺省为false,表示生命周期由SpringApplicationContext管理,设置为true则表示由ServletContainer管理
//        filterRegistration.addInitParameter("targetFilterLifecycle", "true");
//        filterRegistration.setEnabled(true);
//        filterRegistration.addUrlPatterns("/*");
//        return filterRegistration;
//    }
//
//    @Bean(name = "lifecycleBeanPostProcessor")
//    public LifecycleBeanPostProcessor getLifecycleBeanPostProcessor() {
//        return new LifecycleBeanPostProcessor();
//    }
//
//    @Bean
//    public DefaultAdvisorAutoProxyCreator getDefaultAdvisorAutoProxyCreator() {
//        DefaultAdvisorAutoProxyCreator daap = new DefaultAdvisorAutoProxyCreator();
//        daap.setProxyTargetClass(true);
//        return daap;
//    }
//
//    @Bean
//    public AuthorizationAttributeSourceAdvisor getAuthorizationAttributeSourceAdvisor(SecurityManager securityManager) {
//        AuthorizationAttributeSourceAdvisor aasa = new AuthorizationAttributeSourceAdvisor();
//        aasa.setSecurityManager(securityManager);
//        return aasa;
//    }

//    /**
//     * CAS过滤器
//     *
//     * @return
//     * @author SHANHY
//     * @create  2016年1月17日
//     */
//    @Bean(name = "casFilter")
//    public CasFilter getCasFilter() {
//        CasFilter casFilter = new CasFilter();
//        casFilter.setName("casFilter");
//        casFilter.setEnabled(true);
//        // 登录失败后跳转的URL，也就是 Shiro 执行 CasRealm 的 doGetAuthenticationInfo 方法向CasServer验证tiket
//        casFilter.setFailureUrl(loginUrl);// 我们选择认证失败后再打开登录页面
//        return casFilter;
//    }
//

    @Bean
    public SecurityManager securityManager() {

        //1、获取 SecurityManager 工厂，此处使用 Ini 配置文件初始化 SecurityManager
//		Factory<SecurityManager> factory =
//				new WebIniSecurityManagerFactory(Ini.fromResourcePath("classpath:spring-shiro-web.xml"));//
        //2、得到 SecurityManager 实例 并绑定给 SecurityUtils
//		DefaultWebSecurityManager  securityManager = (DefaultWebSecurityManager)factory.getInstance();
//		DefaultWebSecurityManager securityManager =  new DefaultWebSecurityManager();
//		securityManager = factory.getInstance();
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();

        securityManager.setRememberMeManager(rememberMeManager());
//		SessionManager sessionManager=new ServletContainerSessionManager();
        securityManager.setSessionManager(sessionManager());

        //设置realm
        securityManager.setRealm(myShiroRealm());
//        securityManager.setRealm(myShiroCasRealm());
        return securityManager;
    }

    /**
     * 身份认证realm;
     * (这个需要自己写，账号密码校验；权限等)
     *
     * @return
     */
    @Bean
    public MyShiroRealm myShiroRealm() {
        MyShiroRealm myShiroRealm = new MyShiroRealm();
        myShiroRealm.setCredentialsMatcher(hashedCredentialsMatcher());
        return myShiroRealm;
    }

    /**
     * 回话管理
     *
     * @return
     */
    @Bean
    public SessionManager sessionManager() {
        DefaultWebSessionManager sessionManager = new DefaultWebSessionManager();
        Collection<SessionListener> listeners = new ArrayList<SessionListener>();
        listeners.add(new MySessionListener());
        sessionManager.setSessionListeners(listeners);
        sessionManager.setGlobalSessionTimeout(336000);
        return sessionManager;
    }

    /**
     * EhCacheManager管理
     *
     * @return
     */
    @Bean
    public EhCacheManager ehCacheManager() {
        EhCacheManager ehCacheManager = new EhCacheManager();
        //ehCacheManager.setCacheManagerConfigFile("classpath:encache.xml");
        return ehCacheManager;
    }

    /**
     * 在线人数控制
     *
     * @return
     */
    @Bean
    public KickoutSessionControlFilter getKickoutSessionControlFilter() {
        KickoutSessionControlFilter kickoutSessionControlFilter = new KickoutSessionControlFilter();
        //ehCacheManager.setCacheManagerConfigFile("classpath:encache.xml");
        kickoutSessionControlFilter.setSessionManager(sessionManager());
        kickoutSessionControlFilter.setCacheManager(ehCacheManager());
        return kickoutSessionControlFilter;
    }

    /**
     * 设置cookie
     *
     * @return
     */
    @Bean
    public RememberMeManager rememberMeManager() {
        CookieRememberMeManager cookieRememberMeManager = new CookieRememberMeManager();
        SimpleCookie simpleCookie = new SimpleCookie();
        simpleCookie.setName("rememberMe");
        simpleCookie.setHttpOnly(true);
        simpleCookie.setMaxAge(2592000);
        byte[] cipherKey = Base64.decode("4AvVhmFLUs0KTA3Kprsdag==");
        cookieRememberMeManager.setCipherKey(cipherKey);
        cookieRememberMeManager.setCookie(simpleCookie);
        return cookieRememberMeManager;
    }

//	/**
//	 * 用来开启记录密码
//	 * @return
//	 */
//	@Bean
//	public FormAuthenticationFilter formAuthenticationFilter(){
//		FormAuthenticationFilter formAuthenticationFilter =new FormAuthenticationFilter();
//		formAuthenticationFilter.setRememberMeParam("rememberMe");
////		formAuthenticationFilter.setEnabled(true);
////		formAuthenticationFilter.setRememberMeParam("rememberMe");
//		return formAuthenticationFilter;
//	}

    /**
     * 凭证匹配器
     * （由于我们的密码校验交给Shiro的SimpleAuthenticationInfo进行处理了
     * 所以我们需要修改下doGetAuthenticationInfo中的代码;
     * ）
     *
     * @return
     */
    @Bean
    public HashedCredentialsMatcher hashedCredentialsMatcher() {
        HashedCredentialsMatcher hashedCredentialsMatcher = new HashedCredentialsMatcher();
        hashedCredentialsMatcher.setHashAlgorithmName("md5");//散列算法:这里使用MD5算法;
        hashedCredentialsMatcher.setHashIterations(2);//散列的次数，比如散列两次，相当于 md5(md5(""));
        return hashedCredentialsMatcher;
    }

    /**
     * 开启shiro aop注解支持.
     * 使用代理方式;所以需要开启代码支持;
     *
     * @param securityManager
     * @return
     */
    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(SecurityManager securityManager) {
        AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor = new AuthorizationAttributeSourceAdvisor();
        authorizationAttributeSourceAdvisor.setSecurityManager(securityManager);
        return authorizationAttributeSourceAdvisor;
    }

}
