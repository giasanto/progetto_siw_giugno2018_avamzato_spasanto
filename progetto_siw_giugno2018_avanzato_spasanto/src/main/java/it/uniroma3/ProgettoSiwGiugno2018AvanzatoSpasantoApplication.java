package it.uniroma3;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import it.uniroma3.model.Allievo;
import it.uniroma3.model.Attivita;
import it.uniroma3.model.Azienda;
import it.uniroma3.model.Centro;
import it.uniroma3.model.Responsabile;
import it.uniroma3.service.AllievoService;
import it.uniroma3.service.AttivitaService;
import it.uniroma3.service.AziendaService;
import it.uniroma3.service.CentroService;
import it.uniroma3.service.ResponsabileService;

@SpringBootApplication
public class ProgettoSiwGiugno2018AvanzatoSpasantoApplication {
	
	@Autowired
	private AllievoService allievoService;
	
	@Autowired
	private AttivitaService attivitaService;
	
	@Autowired
	private AziendaService aziendaService;
	
	@Autowired
	private CentroService centroService;
	
	@Autowired
	private ResponsabileService responsabileService;

	public static void main(String[] args) {
		SpringApplication.run(ProgettoSiwGiugno2018AvanzatoSpasantoApplication.class, args);
	}
	
	@PostConstruct
	public void init(){
		Allievo allievo = new Allievo("Paolo", "Rossi", "paolo.rossi@email.com", "069855936" , "06/05/98", "Padova");
		allievoService.save(allievo);
		for(Allievo a : allievoService.findByNome("Paolo")) {
			System.out.println(a.getNome());
		}
		Attivita attivita = new Attivita("Calcio", "11/11/11", "12.12");
		attivitaService.save(attivita);
		for(Attivita a : attivitaService.findByNome("Calcio")) {
			System.out.println(a.getNome());
		}
		Azienda azienda= new Azienda("TuttoDivertimento");
		aziendaService.save(azienda);
		for(Azienda a : aziendaService.findByNome("TuttoDivertimento")) {
			System.out.println(a.getNome());
		}
		Centro centro= new Centro("IstitutoFun","Via Marche", "istituto.fun@email.com", "123456789", "200");
		centroService.save(centro);
		for(Centro c : centroService.findByNome("IstitutoFun")) {
			System.out.println(c.getNome());
		}
		Responsabile responsabile= new Responsabile("Luigi", "luigi.bianchi@email.com");
		responsabileService.save(responsabile);
		for(Responsabile r : responsabileService.findByNome("Luigi")) {
			System.out.println(r.getNome());
		}
	}
}
