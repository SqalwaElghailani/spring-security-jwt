package faculte.service_security.service;

import faculte.service_security.dto.RequestUserDto;
import faculte.service_security.dto.ResponseUserDto;
import faculte.service_security.entities.Role;
import faculte.service_security.entities.User;
import faculte.service_security.mappers.UserMapper;
import faculte.service_security.repository.RoleRepository;
import faculte.service_security.repository.UserRepository;
import jakarta.transaction.Transactional;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;
@Service
@Transactional
public class AccountServiceImpl implements AccountService {
    private UserRepository userRepository;
    private  RoleRepository roleRepository;
    private UserMapper userMapper;
    private PasswordEncoder passwordEncoder;


    public AccountServiceImpl(UserRepository userRepository, UserMapper userMapper,
                              PasswordEncoder passwordEncoder,
                              RoleRepository roleRepository) {
        this.userRepository = userRepository;
        this.userMapper = userMapper;
        this.passwordEncoder = passwordEncoder;
        this.roleRepository = roleRepository;

    }
    @Override
    public ResponseUserDto addUser(RequestUserDto request) {
        if (userRepository.findByUsername(request.getUsername()).isPresent()) {
            throw new RuntimeException("Username already exists: " + request.getUsername());
        }

        // Trouver le rôle
        Role role = roleRepository.findByName(String.valueOf(request.getRole()));
        if (role == null) {
            throw new RuntimeException("Role not found: " + request.getRole());
        }
        User user = userMapper.DTO_to_Entity(request);
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole(Collections.singletonList(role));
        User saved_user = userRepository.save(user);
        return userMapper.Entity_to_DTO(saved_user);
    }

    @Override
    public Role addRole(Role role) {
        return null;
    }

    @Override
    public void addRoleToUser(User user, Role role) {

    }

    @Override
    public ResponseUserDto loadUserByUsername(String username) {
        return null;
    }

    @Override
    public List<ResponseUserDto> users() {
        return List.of();
    }
}
