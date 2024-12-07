package com.example.jwtAuth.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;



@RestController
@RequestMapping("/api/products")
public class productController {
    @GetMapping
    public String infoForAuthUsers(){
        return "You get for example products list cause you're auth, no matter your role";
    }
}
