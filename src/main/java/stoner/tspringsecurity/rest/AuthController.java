package stoner.tspringsecurity.rest;

import com.alibaba.fastjson.JSON;
import com.fasterxml.jackson.annotation.JsonAlias;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import stoner.tspringsecurity.bean.User;

@Controller
public class AuthController {

    @RequestMapping("/admin/back")
    @ResponseBody
    public String adminBack(String username, String password) {
        System.out.println("/adminBack");
        System.out.println(username);
        System.out.println(password);
        return "adminBack";
    }

    @RequestMapping("/admin/front")
    @ResponseBody
    public String adminFront(String username, String password) {
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return JSON.toJSONString(principal);
    }

}
