package spring.security.jwt.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import spring.security.jwt.model.User;
import spring.security.jwt.repository.UserRepository;

@Service
public class UserService {

    @Autowired
    private UserRepository repository;

    @Autowired
    private PasswordEncoder encoder;

    public void createUser(User user){
        String pass = user.getPassword();
        user.setPassword(encoder.encode(pass));
        repository.save(user);
    }
}
