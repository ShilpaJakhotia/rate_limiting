package com.grid.owasp.owasp;

import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
@RequestMapping("/employee")
public class EmployeeController {

    List<Employee> employees = new ArrayList<>(
            List.of(Employee.builder().id(1).name("Emp1").address("Bangalore").salary(1000).build(),
                    Employee.builder().id(2).name("Emp2").address("Solapur").salary(2000).build(),
                    Employee.builder().id(3).name("Emp3").address("Solapur").salary(3000).build(),
                    Employee.builder().id(4).name("Emp4").address("Pune").salary(4000).build(),
                    Employee.builder().id(5).name("Emp5").address("Hyderabad").salary(5000).build())
    );

    @PostMapping
    public boolean addEmployee(@RequestBody Employee newEmployee) {
        return employees.add(newEmployee);
    }

    @DeleteMapping("/{id}")
    public Employee addEmployee(@PathVariable int id) {
        return employees.remove(id);
    }

    @GetMapping
    public List<Employee> allEmployees() {
        return employees;
    }



}
