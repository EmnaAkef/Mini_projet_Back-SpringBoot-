package com.emna.films.repos;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;
import org.springframework.web.bind.annotation.CrossOrigin;

import com.emna.films.entities.Genre;

@RepositoryRestResource(path = "genre")
@CrossOrigin(origins="http://localhost:4200/")
public interface GenreRepository  extends JpaRepository<Genre, Long>{

}
