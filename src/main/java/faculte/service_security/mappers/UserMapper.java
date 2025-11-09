package faculte.service_security.mappers;

import faculte.service_security.dto.RequestUserDto;
import faculte.service_security.dto.ResponseUserDto;
import faculte.service_security.entities.User;
import org.springframework.beans.BeanUtils;
import org.springframework.stereotype.Component;

@Component
public class UserMapper {
    public User DTO_to_Entity(RequestUserDto request){
        User user = new User();
        user.setUsername(request.getUsername());
        user.setPassword(request.getPassword());
        //BeanUtils.copyProperties(request,user);
        return user;
    }
    public ResponseUserDto Entity_to_DTO(User user){
        ResponseUserDto response = new ResponseUserDto();
        response.setId(user.getId());
        response.setUsername(user.getUsername());

        if (user.getRole() != null && !user.getRole().isEmpty()) {
            response.setRole(user.getRole().iterator().next().getName());
        }
        // BeanUtils.copyProperties(user,response);
        return response;
    }
}
