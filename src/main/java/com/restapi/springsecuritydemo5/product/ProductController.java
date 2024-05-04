package com.restapi.springsecuritydemo5.product;

import java.util.List;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/product")
@RequiredArgsConstructor
public class ProductController {

    private final ProductService productService;

    // http://localhost:8080/product
    @PreAuthorize("hasRole('PRODUCT_SELECT')")
    @GetMapping
    public List<Product> listAll(){
        return productService.listAll();
    }

    @PreAuthorize("hasRole('PRODUCT_INSERT')")
    @PostMapping
    public Product create(@RequestBody Product product){
        return productService.create(product);
    }

    @PreAuthorize("hasRole('PRODUCT_UPDATE')")
    @PutMapping
    public Product update(@RequestBody Product product){
        return productService.update(product);
    }

    @PreAuthorize("hasRole('PRODUCT_DELETE')")
    @DeleteMapping
    public void delete(@RequestParam("id") Long id){
        productService.delete(id);
    }
    
}
