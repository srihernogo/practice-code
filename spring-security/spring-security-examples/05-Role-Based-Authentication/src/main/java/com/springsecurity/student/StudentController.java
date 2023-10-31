package com.springsecurity.student;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("api/v1/students")
public class StudentController
{
    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1, "Jack"),
            new Student(2, "Jill"),
            new Student(3, "Smith"));

    @GetMapping("{studentId}")
    public Student getStudent(@PathVariable("studentId") Integer studentId)
    {
        System.out.println("GET Students Called");

        return STUDENTS.stream()
                .filter(student -> studentId.equals(student.getStudentId()))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Student " + studentId + " doesn't exist"));
    }
}
