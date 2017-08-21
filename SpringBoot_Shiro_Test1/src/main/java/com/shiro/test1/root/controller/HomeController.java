package com.shiro.test1.root.controller;
import com.shiro.test1.config.shiro.MyShiroRealm;
import com.shiro.test1.config.shiro.ShiroConfiguration;
import com.shiro.test1.core.service.UserInfoService;
import org.apache.commons.collections.map.HashedMap;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.util.Iterator;
import java.util.Map;

@Controller
public class HomeController {

    @Resource
    private UserInfoService userInfoService;

    @RequestMapping({"/", "/index"})
    public String index() {
//        UsernamePasswordToken usernamePasswordToken=new UsernamePasswordToken("admin","123456",true);
        Subject subject = SecurityUtils.getSubject();
//        subject.login(usernamePasswordToken);
        System.out.println("value1:"+subject.isRemembered());
        System.out.println("value2:"+subject.isAuthenticated());
        return "/index";
    }

    @RequestMapping({"/userInfo"})
    @ResponseBody
    public String userInfo(String username, String password) {
        //1、获取 SecurityManager 工厂，此处使用 Ini 配置文件初始化 SecurityManager
        Factory<org.apache.shiro.mgt.SecurityManager> factory =
                new IniSecurityManagerFactory("classpath:shiro.ini");
//2、得到 SecurityManager 实例 并绑定给 SecurityUtils
        org.apache.shiro.mgt.SecurityManager securityManager = factory.getInstance();
        SecurityUtils.setSecurityManager(securityManager);
//        DefaultWebSecurityManager securityManager =  new DefaultWebSecurityManager();
//        //设置realm.
//        securityManager.setRealm(new MyShiroRealm());

        SecurityUtils.setSecurityManager(securityManager);
        //3、得到 Subject 及创建用户名/密码身份验证 Token（即用户身份/凭证）
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken(username, password);
        token.setRememberMe(true);
        try {
        //4、登录，即身份验证
            subject.login(token);
            return "success";
        } catch (AuthenticationException e) {
            return "fail";
        //5、身份验证失败
        }
        //6、退出
//        subject.logout();
//        return "success";
    }

    @RequestMapping(value = "/login", method = RequestMethod.GET)
    public String login() {
        return "login";
    }

    @RequestMapping(value = "/out", method = RequestMethod.GET)
    public String out() {
        Subject subject = SecurityUtils.getSubject();
        System.out.println("value1:"+subject.isRemembered());
        System.out.println("value2:"+subject.isAuthenticated());
        return "out";
    }

    @RequestMapping(value = "/getSession", method = RequestMethod.GET)
    @ResponseBody
    public Map<String,Object> getSession() {
        Map<String, Object> map=new HashedMap();
        Subject subject = SecurityUtils.getSubject();
        Session session = subject.getSession();
        map.put("id",session.getId());
        map.put("host",session.getHost());
        map.put("timeOut",session.getTimeout());
        map.put("startTime",session.getStartTimestamp());
        map.put("lastTime",session.getLastAccessTime());
        return map;
    }

    @RequestMapping(value = "/setSession", method = RequestMethod.GET)
    @ResponseBody
    public Map<String,Object> setSession() {
        Map<String, Object> map=new HashedMap();
        Subject subject = SecurityUtils.getSubject();
        Session session = subject.getSession();
        map.put("id",session.getId());
        map.put("host",session.getHost());
        map.put("timeOut",session.getTimeout());
        map.put("startTime",session.getStartTimestamp());
        map.put("lastTime",session.getLastAccessTime());
        session.setTimeout(1);
//        session.removeAttribute(session);
        return map;
    }

    @RequestMapping(value = "/delSession", method = RequestMethod.GET)
    @ResponseBody
    public Map<String,Object> delSession() {
        Map<String, Object> map=new HashedMap();
        Subject subject = SecurityUtils.getSubject();
        Session session = subject.getSession();
        map.put("id",session.getId());
        map.put("host",session.getHost());
        map.put("timeOut",session.getTimeout());
        map.put("startTime",session.getStartTimestamp());
        map.put("lastTime",session.getLastAccessTime());
//        session.setTimeout(1);
       Iterator<Object> it=session.getAttributeKeys().iterator();
        while(it.hasNext()){
            System.out.println(it.next());
        }
        return map;
    }

    @RequestMapping(value = "/out", method = RequestMethod.POST)
    public String out(Map<String, Object> map) {
        Subject subject = SecurityUtils.getSubject();
        subject.logout();
        map.put("msg", "success");
        return "out";
    }

    // 登录提交地址和applicationontext-shiro.xml配置的loginurl一致。 (配置文件方式的说法)
    @RequestMapping(value = "/login", method = RequestMethod.POST)
    public String login(HttpServletRequest request,Map<String, Object> map) throws Exception {
        String exception = (String) request.getAttribute("shiroLoginFailure");
        System.out.println("exception=" + exception);
        String msg = "";
        if (exception != null) {
            if (UnknownAccountException.class.getName().equals(exception)) {
                System.out.println("UnknownAccountException -- > 账号不存在：");
                msg = "UnknownAccountException -- > 账号不存在：";
            } else if (IncorrectCredentialsException.class.getName().equals(exception)) {
                System.out.println("IncorrectCredentialsException -- > 密码不正确：");
                msg = "IncorrectCredentialsException -- > 密码不正确：";
            } else if ("kaptchaValidateFailed".equals(exception)) {
                System.out.println("kaptchaValidateFailed -- > 验证码错误");
                msg = "kaptchaValidateFailed -- > 验证码错误";
            } else {
                msg = "else >> " + exception;
                System.out.println("else -- >" + exception);
            }
        }
        Subject subject = SecurityUtils.getSubject();
//        UsernamePasswordToken usernamePasswordToken= ((UsernamePasswordToken)subject.isRemembered());
//        System.out.println(usernamePasswordToken.isRememberMe());
//        usernamePasswordToken.setRememberMe(true);
        System.out.println(subject.isRemembered());
        map.put("msg", msg);
        return "redirect:" + ShiroConfiguration.loginUrl;
        // 此方法不处理登录成功,由shiro进行处理.
//        return "index";
    }
}
