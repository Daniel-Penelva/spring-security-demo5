package com.restapi.springsecuritydemo5.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class Controller {

    // http://localhost:8080/api
    @GetMapping
    public String getOla(){
        return "Tudo funcionando";
    }
    
}
