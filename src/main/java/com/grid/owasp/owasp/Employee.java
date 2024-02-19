package com.grid.owasp.owasp;

import lombok.*;

import java.util.Objects;

@Getter
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Employee {
    int id;
    String name;
    String address;
    int salary;

    @Override
    public String toString() {
        return "Employee{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", address='" + address + '\'' +
                ", salary=" + salary +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Employee employee = (Employee) o;
        return id == employee.id && salary == employee.salary && Objects.equals(name, employee.name) && Objects.equals(address, employee.address);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, name, address, salary);
    }
}
