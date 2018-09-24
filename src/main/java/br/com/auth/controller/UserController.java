package br.com.auth.controller;

import br.com.auth.domain.User;
import br.com.auth.service.UserService;
import br.com.spacebox.common.model.request.LoginRequest;
import br.com.spacebox.common.model.request.UserRequest;
import br.com.spacebox.common.model.response.TokenResponse;
import br.com.spacebox.common.model.response.UserResponse;
import br.com.spacebox.common.security.PrincipalToken;
import io.swagger.annotations.*;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/users")
@Api(tags = "users")
@CrossOrigin
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private ModelMapper modelMapper;

    @PostMapping("/")
    @ApiOperation(value = "Creates user and returns its JWT token.")
    @ApiResponses(value = {
            @ApiResponse(code = 400, message = "Something went wrong"),
            @ApiResponse(code = 403, message = "Access denied"),
            @ApiResponse(code = 422, message = "Username is already in use"),
            @ApiResponse(code = 500, message = "Expired or invalid JWT token")
    })
    public void signup(@ApiParam("Signup User") @RequestBody UserRequest user) {
        userService.create(modelMapper.map(user, User.class));
    }

    @DeleteMapping(value = "/")
    @ApiOperation(value = "Delete user")
    @ApiResponses(value = {
            @ApiResponse(code = 400, message = "Something went wrong"),
            @ApiResponse(code = 403, message = "Access denied"),
            @ApiResponse(code = 404, message = "The user doesn't exist"),
            @ApiResponse(code = 500, message = "Expired or invalid JWT token")
    })
    public void delete(PrincipalToken token) {
        userService.delete(token.getUserDetailsAuth());
    }

    @PatchMapping(value = "/")
    @ApiOperation(value = "Update user")
    @ApiResponses(value = {
            @ApiResponse(code = 400, message = "Something went wrong"),
            @ApiResponse(code = 403, message = "Access denied"),
            @ApiResponse(code = 404, message = "The user doesn't exist"),
            @ApiResponse(code = 500, message = "Expired or invalid JWT token")
    })
    public void update(PrincipalToken token, @ApiParam("Update User") @RequestBody UserRequest user) {
        userService.update(token.getUserDetailsAuth(), modelMapper.map(user, User.class));
    }

    @GetMapping(value = "/")
    @ApiOperation(value = "Returns current user data", response = UserResponse.class)
    @ApiResponses(value = {
            @ApiResponse(code = 400, message = "Something went wrong"),
            @ApiResponse(code = 403, message = "Access denied"),
            @ApiResponse(code = 500, message = "Expired or invalid JWT token")
    })
    public UserResponse detail(PrincipalToken token) {
        return modelMapper.map(userService.find(token.getUserDetailsAuth().getUsername()), UserResponse.class);
    }

    @PostMapping("/login")
    @ApiOperation(value = "Authenticates user and returns its JWT token.")
    @ApiResponses(value = {
            @ApiResponse(code = 400, message = "Something went wrong"),
            @ApiResponse(code = 422, message = "Invalid login/password supplied")
    })
    public TokenResponse login(@ApiParam("Login Data") @RequestBody LoginRequest request) {
        return userService.login(request.getUsername(), request.getPassword());
    }

    @PostMapping("/logout")
    @ApiOperation(value = "Logoff user.")
    @ApiResponses(value = {
            @ApiResponse(code = 400, message = "Something went wrong")
    })
    public void logout(PrincipalToken token) {
        userService.logout(token.getUserDetailsAuth().getUsername());
    }
}