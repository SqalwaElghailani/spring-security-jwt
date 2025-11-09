package faculte.service_security.web;

import faculte.service_security.dto.RequestUserDto;
import faculte.service_security.dto.ResponseUserDto;
import faculte.service_security.service.AccountService;
import faculte.service_security.service.AccountServiceImpl;
import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.servers.Server;
import org.apache.catalina.User;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@OpenAPIDefinition(
        info = @Info(
                title = "Gestion des users",
                description = "cette offre tous les méthodes pour gérer les utilisateur",
                version = "1.0.0"
        ),
        servers = @Server(
                url = "http://localhost:8087"
        )
)
@RestController
@RequestMapping("/v1/users")
public class API {
    private AuthenticationManager authenticationManager;
    private UserDetailsService userDetailsService;
    private JwtEncoder jwtEncoder;
    private JwtDecoder jwtDecoder;
    private AccountServiceImpl userService;

    public API(AuthenticationManager authenticationManager, UserDetailsService userDetailsService, JwtEncoder jwtEncoder, JwtDecoder jwtDecoder, AccountServiceImpl userService) {
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
        this.jwtEncoder = jwtEncoder;
        this.jwtDecoder = jwtDecoder;
        this.userService = userService;
    }

    @Operation(
            summary = " Ajouter un utilisateur",
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    required = true,
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = RequestUserDto.class )
                    )
            ),
            responses = {
                    @ApiResponse(responseCode = "200", description = "bien enregiter",
                            content = @Content(
                                    mediaType = "application/json",
                                    schema = @Schema(implementation = ResponseUserDto.class )
                            )
                    ),

                    @ApiResponse(responseCode = "4xx",description = "erreur client"),
                    @ApiResponse(responseCode = "5xx",description = "erreur serveur"),
            }
    )
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @PostMapping("/add")
    public ResponseEntity<ResponseUserDto> add(@RequestBody RequestUserDto requestUserDto) {
        ResponseUserDto response = userService.addUser(requestUserDto);
        return ResponseEntity.ok(response);
    }
    @PostMapping("/login")
    Map<String,String> login(String username, String password){
        Map<String,String> ID_token = new HashMap<>();
        Instant instant = Instant.now();
        //veriffier l'authentification
        Authentication authenticate = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username,password)
        );
 //get scope
        String scope = authenticate.getAuthorities().stream().map(auth -> auth.getAuthority()).collect(Collectors.joining(""));
        // création des ID Token

        //1-  Access token
        JwtClaimsSet jwtClaimsSet_accessToken = JwtClaimsSet.builder()
                .subject(authenticate.getName())
                .issuer("Security_service")
                .issuedAt(instant)
                .expiresAt(instant.plus(2, ChronoUnit.MINUTES))
                .claim("scope",scope)
                .build();

        String Access_token= jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet_accessToken)).getTokenValue();


        //Refresh token
        JwtClaimsSet jwtClaimsSet_RefreshToken = JwtClaimsSet.builder()
                .subject(authenticate.getName())
                .issuer("Security_service")
                .issuedAt(instant)
                .expiresAt(instant.plus(15, ChronoUnit.MINUTES))
                .build();

        String Refresh_token= jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet_accessToken)).getTokenValue();

        ID_token.put("access_token",Access_token);
        ID_token.put("refresh_token",Refresh_token);

        return ID_token;


//refresh token

}
    @PostMapping("/refresh")
    public Map<String, String> refresh(@RequestBody Map<String, String> requestBody) {
        Map<String, String> ID_token = new HashMap<>();
        Instant instant = Instant.now();

        String refreshToken = requestBody.get("refreshToken");

        if (refreshToken == null || refreshToken.trim().isEmpty()) {
            ID_token.put("error", "refresh token is null " + HttpStatus.UNAUTHORIZED);
            return ID_token;
        }

        try {
            // verifier la signature
            Jwt decoded = jwtDecoder.decode(refreshToken);
            String username = decoded.getSubject();
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            // creation Access Token
            String scope = userDetails.getAuthorities().stream()
                    .map(auth -> auth.getAuthority())
                    .collect(Collectors.joining(" "));

            JwtClaimsSet jwtClaimsSet_accessToken = JwtClaimsSet.builder()
                    .subject(userDetails.getUsername())
                    .issuer("Security_Service")
                    .issuedAt(instant)
                    .expiresAt(instant.plus(30, ChronoUnit.MINUTES)) // زد المدة إلى 30 دقيقة
                    .claim("scope", scope)
                    .build();

            String Access_Token = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet_accessToken)).getTokenValue();

            ID_token.put("access_token", Access_Token);
            ID_token.put("refresh_token", refreshToken);
            ID_token.put("token_type", "Bearer");
            ID_token.put("expires_in", "1800"); // 30 دقيقة بالثواني
            return ID_token;

        } catch (Exception e) {
            ID_token.put("error", "Invalid refresh token: " + e.getMessage());
            return ID_token;
        }
    }
//    @PostMapping("/refresh")
//    public Map<String,String> refresh(String refreshToken){
//        Map<String,String> ID_token = new HashMap<>();
//        Instant instant = Instant.now();
//
//        if(refreshToken == null || refreshToken.trim().isEmpty()){
//            ID_token.put("error", "refresh token is null " + HttpStatus.UNAUTHORIZED);
//            return ID_token;
//        }
//
//        try {
//            // verifier la signature
//            Jwt decoded = jwtDecoder.decode(refreshToken);
//            String username = decoded.getSubject();
//            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
//
//            // creation Access Token
//            String scope = userDetails.getAuthorities().stream()
//                    .map(auth -> auth.getAuthority())
//                    .collect(Collectors.joining(" "));
//
//            JwtClaimsSet jwtClaimsSet_accessToken = JwtClaimsSet.builder()
//                    .subject(userDetails.getUsername())
//                    .issuer("Security_Service")
//                    .issuedAt(instant)
//                    .expiresAt(instant.plus(2, ChronoUnit.MINUTES))
//                    .claim("scope", scope)
//                    .build();
//
//            String Access_Token = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet_accessToken)).getTokenValue();
//
//            ID_token.put("access_token", Access_Token);
//            ID_token.put("refresh_token", refreshToken);
//            return ID_token;
//
//        } catch (Exception e) {
//            ID_token.put("error", "Invalid refresh token: " + e.getMessage());
//            return ID_token;
//        }
//    }
}