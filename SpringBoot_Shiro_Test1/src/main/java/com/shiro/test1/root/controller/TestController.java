package com.shiro.test1.root.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * Created by qiang on 2017/8/22.
 */

@Controller
@RequestMapping(value = "shiro")
public class TestController {

    @RequestMapping({"/index"})
    @ResponseBody
    public String casIndex() {
        return "shiro-index";
    }

    @RequestMapping({"/login"})
    @ResponseBody
    public String casLogin() {
        return "shiro-login";
    }

    @RequestMapping({"/out"})
    @ResponseBody
    public String casOut() {
        return "shiro-out";
    }
}
