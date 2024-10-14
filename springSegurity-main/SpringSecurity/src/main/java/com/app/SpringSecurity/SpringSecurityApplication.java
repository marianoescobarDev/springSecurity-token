package com.app.SpringSecurity;

import com.app.SpringSecurity.persistencia.entidades.RolesEnum;
import com.app.SpringSecurity.persistencia.entidades.niveles;
import com.app.SpringSecurity.persistencia.entidades.permisos;
import com.app.SpringSecurity.persistencia.entidades.usuarios;
import com.app.SpringSecurity.repository.usuarioRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.List;
import java.util.Set;

@SpringBootApplication
public class SpringSecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityApplication.class, args);}


	@Bean
	CommandLineRunner init(usuarioRepository usuarioRepository){
		return args -> {
			permisos createPermiso = permisos.builder()
					.nombre("CREATE")
					.build();

			permisos readPermiso = permisos.builder()
					.nombre("READ")
					.build();
			permisos updatePermiso = permisos.builder()
					.nombre("UPDATE")
					.build();
			permisos deletePermiso = permisos.builder()
					.nombre("DELETE")
					.build();

			permisos refactorPermiso = permisos.builder()
					.nombre("REFACTOR")
					.build();

			niveles adminNivel = niveles.builder()
					.roleEnum(RolesEnum.ADMIN)
					.permisos(Set.of(createPermiso,deletePermiso,readPermiso, updatePermiso))
					.build();

			niveles invitadoNivel = niveles.builder()
					.roleEnum(RolesEnum.INVITADO)
					.permisos(Set.of(readPermiso))
					.build();

			niveles developerNivel = niveles.builder()
					.roleEnum(RolesEnum.DEVELOPER)
					.permisos(Set.of(readPermiso,createPermiso,deletePermiso,updatePermiso,refactorPermiso))
					.build();

			usuarios mariano = usuarios.builder()
					.nombre("mariano")
					.clave(new BCryptPasswordEncoder().encode("1234"))
					.accountNoExpired(true)
					.accountNoLocked(true)
					.credentialNoExpired(true)
					.isEnable(true)
					.niveles(Set.of(developerNivel))
					.build();

			usuarios yona = usuarios.builder()
					.nombre("yona")
					.clave(new BCryptPasswordEncoder().encode("1234"))
					.accountNoExpired(true)
					.credentialNoExpired(true)
					.accountNoLocked(true)
					.isEnable(true)
					.niveles(Set.of(adminNivel))
					.build();

			usuarios gabi = usuarios.builder()
					.nombre("gabi")
					.clave(new BCryptPasswordEncoder().encode("1234"))
					.accountNoExpired(true)
					.credentialNoExpired(true)
					.accountNoLocked(true)
					.isEnable(true)
					.niveles(Set.of(invitadoNivel))
					.build();

			usuarioRepository.saveAll(List.of(mariano,yona,gabi));


		};
	}

}
