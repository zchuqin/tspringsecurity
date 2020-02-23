package stoner.tspringsecurity.service;

import com.alibaba.fastjson.JSON;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.util.DigestUtils;
import stoner.tspringsecurity.bean.Role;
import stoner.tspringsecurity.bean.User;
import stoner.tspringsecurity.handler.MyPasswordEncoder;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;

@Service
public class UserService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        ArrayList<Role> roles = new ArrayList<>();
        roles.add(new Role("系统管理员"));
        roles.add(new Role("一级用户"));
        User user = new User();
        user.setUsername("harry");
        user.setPassword(MyPasswordEncoder.digest("2346"));
        user.setAddress("*******");
        user.setEnabled(true);
        user.setRoles(roles);
        System.out.println(JSON.toJSONString(user));
        return user;
    }

    public boolean hasPermission(HttpServletRequest request, Authentication authentication) {
        if (authentication.getPrincipal() instanceof User) {
            System.out.println(JSON.toJSONString(authentication.getCredentials()));
            return ((User) authentication.getPrincipal()).getAddress() != null;
        }
        return false;
    }
}
