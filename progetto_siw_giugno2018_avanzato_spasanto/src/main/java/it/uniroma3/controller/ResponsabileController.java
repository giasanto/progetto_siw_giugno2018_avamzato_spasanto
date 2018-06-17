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

import it.uniroma3.controller.validator.ResponsabileValidator;
import it.uniroma3.model.Responsabile;
import it.uniroma3.service.ResponsabileService;

@Controller
public class ResponsabileController {
	@Autowired
	private ResponsabileService responsabileService;

	@Autowired
	private ResponsabileValidator validator;

	@RequestMapping("/responsabili")
	public String responsabili(Model model) {
		model.addAttribute("responsabili", this.responsabileService.findAll());
		return "responsabileList";
	}

	@RequestMapping("/addResponsabile")
	public String addResponsabile(Model model) {
		model.addAttribute("responsabile", new Responsabile());
		return "responsabileForm";
	}

	@RequestMapping(value = "/responsabile/{id}", method = RequestMethod.GET)
	public String getResponsabile(@PathVariable("id") Long id, Model model) {
		model.addAttribute("responsabile", this.responsabileService.findById(id));
		return "showResponsabile";
	}

	@RequestMapping(value = "/responsabile", method = RequestMethod.POST)
	public String newResponsabile(@Valid @ModelAttribute("responsabile") Responsabile responsabile, Model model, BindingResult bindingResult) {
		this.validator.validate(responsabile, bindingResult);

		if(this.responsabileService.alreadyExists(responsabile)) {
			model.addAttribute("exists", "Responsabile gia' esistente");
			return "responsabileForm";
		} else {
			if(!bindingResult.hasErrors()) {
				this.responsabileService.save(responsabile);
				model.addAttribute("responsabili", this.responsabileService.findAll());
				return "responsabileList";
			}
		}
		return "responsabileForm";
	}
}
