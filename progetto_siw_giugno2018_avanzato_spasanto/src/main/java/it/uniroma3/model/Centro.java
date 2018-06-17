package it.uniroma3.model;

import java.util.List;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.OneToMany;
import javax.persistence.OneToOne;

@Entity
public class Centro {
	
	@Id
	@GeneratedValue(strategy=GenerationType.AUTO)
	private Long id;
	
	@Column(nullable=false)
	private String nome;
	
	@Column(nullable=false)
	private String indirizzo;
	
	@Column(nullable=false)
	private String email;
	
	@Column(nullable=false)
	private String telefono;
	
	@Column(nullable=false)
	private String capienzaMax;
	
	@OneToMany(mappedBy="centro")
	private List<Attivita> attivita;
	
	@OneToOne
	private Responsabile responsabile;
	
	public Centro() {
	}
	
	public Centro(String nome, String indirizzo, String email, String telefono, String capienzaMax) {
		this.nome = nome;
		this.indirizzo = indirizzo;
		this.email = email;
		this.telefono = telefono;
		this.capienzaMax = capienzaMax;
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getNome() {
		return nome;
	}

	public void setNome(String nome) {
		this.nome = nome;
	}

	public String getIndirizzo() {
		return indirizzo;
	}

	public void setIndirizzo(String indirizzo) {
		this.indirizzo = indirizzo;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getTelefono() {
		return telefono;
	}

	public void setTelefono(String telefono) {
		this.telefono = telefono;
	}

	public String getCapienzaMax() {
		return capienzaMax;
	}

	public void setCapienzaMax(String capienzaMax) {
		this.capienzaMax = capienzaMax;
	}
}
