package br.com.examplejwt.header.repository;

import br.com.examplejwt.header.model.entity.Role;
import br.com.examplejwt.header.model.enums.ERole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {

    Optional<Role> findByName(ERole name);

}
