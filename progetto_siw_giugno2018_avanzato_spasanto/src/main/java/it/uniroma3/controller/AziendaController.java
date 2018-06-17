package it.uniroma3.controller;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import it.uniroma3.controller.validator.AziendaValidator;
import it.uniroma3.model.Azienda;
import it.uniroma3.service.AziendaService;

@Controller
public class AziendaController {
	@Autowired
	private AziendaService aziendaService;

	@Autowired
	private AziendaValidator validator;

	@RequestMapping("/aziende")
	public String aziende(Model model) {
		model.addAttribute("aziende", this.aziendaService.findAll());
		return "aziendaList";
	}

	@RequestMapping("/addAzienda")
	public String addAzienda(Model model) {
		model.addAttribute("azienda", new Azienda());
		return "aziendaForm";
	}

	@RequestMapping(value = "/azienda/{id}", method = RequestMethod.GET)
	public String getAzienda(@PathVariable("id") Long id, Model model) {
		model.addAttribute("azienda", this.aziendaService.findById(id));
		return "showAzienda";
	}

	@RequestMapping(value = "/azienda", method = RequestMethod.POST)
	public String newAzienda(@Valid @ModelAttribute("azienda") Azienda azienda, Model model, BindingResult bindingResult) {
		this.validator.validate(azienda, bindingResult);

		if(this.aziendaService.alreadyExists(azienda)) {
			model.addAttribute("exists", "Azienda gia' esistente");
			return "aziendaForm";
		} else {
			if(!bindingResult.hasErrors()) {
				this.aziendaService.save(azienda);
				model.addAttribute("aziende", this.aziendaService.findAll());
				return "aziendaList";
			}
		}
		return "aziendaForm";
	}
}
