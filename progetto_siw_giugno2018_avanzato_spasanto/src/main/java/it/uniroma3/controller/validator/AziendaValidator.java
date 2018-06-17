package it.uniroma3.controller.validator;

import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.ValidationUtils;
import org.springframework.validation.Validator;

import it.uniroma3.model.Azienda;

@Component
public class AziendaValidator implements Validator {

	@Override
	public boolean supports(Class<?> aClass) {
		return Azienda.class.equals(aClass);
	}

	@Override
	public void validate(Object o, Errors errors) {
		ValidationUtils.rejectIfEmptyOrWhitespace(errors, "nome", "required");
	}
}
