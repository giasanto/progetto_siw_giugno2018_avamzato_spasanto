package it.uniroma3.service;

import java.util.List;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import it.uniroma3.model.Azienda;
import it.uniroma3.repository.AziendaRepository;

@Transactional
@Service
public class AziendaService {

	@Autowired
	private AziendaRepository aziendaRepository;

	public Azienda save(Azienda azienda) {
		return this.aziendaRepository.save(azienda);
	}

	public List<Azienda> findByNome(String nome){
		return this.aziendaRepository.findByNome(nome);
	}

	public List<Azienda> findAll(){
		return (List<Azienda>)this.aziendaRepository.findAll();
	}

	public Azienda findById(Long id){
		Optional<Azienda> azienda = this.aziendaRepository.findById(id);
		if (azienda.isPresent()) 
			return azienda.get();
		else
			return null;
	}

	public boolean alreadyExists(Azienda azienda) {
		List<Azienda> aziende= this.aziendaRepository.findByNome(azienda.getNome());
		if (aziende.size() > 0)
			return true;
		else 
			return false;
	}	
}


