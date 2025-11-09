package faculte.service_security.service;

import faculte.service_security.dto.RequestUserDto;
import faculte.service_security.dto.ResponseUserDto;
import faculte.service_security.entities.Role;
import faculte.service_security.entities.User;

import java.util.List;

public interface AccountService {
    ResponseUserDto addUser(RequestUserDto request);
    Role addRole(Role role);
    void addRoleToUser(User user, Role role);
    ResponseUserDto loadUserByUsername(String username);
    List<ResponseUserDto> users();
}
