package com.lucasoliveira.authentication.repository;

import com.lucasoliveira.authentication.enums.RoleEnum;
import com.lucasoliveira.authentication.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(RoleEnum name);
}
