package exemple.demo.jwtauth;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Home {
    @GetMapping
    public String welcome(){
        return "Welcome Back";
    }

    @GetMapping("/admin")
    public String welcomeAdmin(){
        return "Welcome Back Admin";
    }

    @GetMapping("/user")
    public String welcomeUser(){
        return "Welcome Back User";
    }
}
