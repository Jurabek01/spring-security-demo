package com.example.demo.rest;

import com.example.demo.model.Developer;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@RestController
@RequestMapping("/api/v1/developers")
public class MyController {

    private List<Developer> DEVELOPERS = Stream.of(
            new Developer(1L, "John", "Smith"),
            new Developer(2L, "Jan", "Kowalski"),
            new Developer(3L, "Jan", "Kowalski")
    ).collect(Collectors.toList());

    @GetMapping
    public List<Developer> getAllDevelopers() {
        return DEVELOPERS;
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('developers:read')")// 3 version
    public Developer getDeveloperById(@PathVariable Long id) {
        return DEVELOPERS.stream()
                .filter(developer -> developer.getId().equals(id))
                .findFirst()
                .orElse(null);
    }

    @PostMapping
    @PreAuthorize("hasAuthority('developers:write')") // 3 version
    public Developer addDeveloper(@RequestBody Developer developer) {
        DEVELOPERS.add(developer);
        return developer;
    }

    @DeleteMapping("/{id}")
    public void deleteDeveloper(@PathVariable Long id) {
        DEVELOPERS.removeIf(developer -> developer.getId().equals(id));
    }
}
