package com.Harmoni.Auth.Security.Exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

	@ExceptionHandler(UserNotFoundException.class)
	public ResponseEntity<Map<String, Object>> handleUserNotFoundException(UserNotFoundException ex) {
		Map<String, Object> body = new HashMap<>();
		body.put("errormsg", ex.getMessage());
		return new ResponseEntity<>(body, HttpStatus.NOT_FOUND);
	}

	@ExceptionHandler(ValidateExceptionHandler.class)
	public ResponseEntity<Map<String, Object>> handleValidateException(ValidateExceptionHandler ex) {
		Map<String, Object> body = new HashMap<>();
		body.put("errormsg", ex.getMessage());
		return new ResponseEntity<>(body, HttpStatus.BAD_REQUEST);
	}

	@ExceptionHandler(InternalServerErrorException.class)
	public ResponseEntity<Map<String, Object>> handleInternalServerErrorException(InternalServerErrorException ex) {
		Map<String, Object> body = new HashMap<>();
		body.put("errormsg", ex.getMessage());
		return new ResponseEntity<>(body, HttpStatus.INTERNAL_SERVER_ERROR);
	}

	@ExceptionHandler(UnauthorizedException.class)
	public ResponseEntity<Map<String, Object>> handleUnauthorizedException(UnauthorizedException ex) {
		Map<String, Object> body = new HashMap<>();
		body.put("errormsg", ex.getMessage());
		return new ResponseEntity<>(body, HttpStatus.UNAUTHORIZED);
	}

	@ExceptionHandler(DuplicateExceptionHandler.class)
	public ResponseEntity<Map<String, Object>> handleDuplicateException(DuplicateExceptionHandler ex) {
		Map<String, Object> body = new HashMap<>();
		body.put("errormsg", ex.getMessage());
		return new ResponseEntity<>(body, HttpStatus.CONFLICT);
	}

	@ExceptionHandler(TypeExceptionHandler.class)
	public ResponseEntity<Map<String, Object>> handleTypeException(TypeExceptionHandler ex) {
		Map<String, Object> body = new HashMap<>();
		body.put("errormsg", ex.getMessage());
		return new ResponseEntity<>(body, HttpStatus.UNSUPPORTED_MEDIA_TYPE);
	}
}
