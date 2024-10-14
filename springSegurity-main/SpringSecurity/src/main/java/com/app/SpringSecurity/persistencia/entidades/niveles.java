package com.app.SpringSecurity.persistencia.entidades;


import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.HashSet;
import java.util.Set;

@Builder
@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
public class niveles {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "nivel_nombre")
    @Enumerated(EnumType.STRING)
    private RolesEnum roleEnum;


    @ManyToMany(fetch = FetchType.EAGER, cascade = CascadeType.ALL)
    @JoinTable(name = "nivel_permiso", joinColumns = @JoinColumn(name = "nivel_id") ,inverseJoinColumns = @JoinColumn(name = "permiso_id"))
    private Set<permisos> permisos = new HashSet<>();

}
