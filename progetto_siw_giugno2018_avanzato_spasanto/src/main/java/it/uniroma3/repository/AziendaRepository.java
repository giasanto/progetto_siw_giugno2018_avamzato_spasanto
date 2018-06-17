package it.uniroma3.repository;

import java.util.List;

import org.springframework.data.repository.CrudRepository;

import it.uniroma3.model.Azienda;

public interface AziendaRepository extends CrudRepository<Azienda, Long> {
	
	public List<Azienda> findByNome(String nome);
}
