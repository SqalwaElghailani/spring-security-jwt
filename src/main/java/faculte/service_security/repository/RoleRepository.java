package faculte.service_security.repository;

import faculte.service_security.entities.Role;
import org.springframework.data.jpa.repository.JpaRepository;



public interface RoleRepository extends JpaRepository<Role, Integer> {

    Role findByName(String name);
}
