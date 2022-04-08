<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ taglib prefix = "c" uri = "http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>  
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Insert title here</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-EVSTQN3/azprG1Anm3QDgpJLIm9Nao0Yz1ztcQTwFspd3yD65VohhpuuCOmLASjC" crossorigin="anonymous">
</head>
<body>

	<div class="container">
		<div class="row">
			
			<div class="col-6">
				<h2>Regístrate</h2>
				<form:form method="post" action="/register" modelAttribute="nuevoUsuario">
					
					<div class="form-group">
						<form:label path="name">Nombre:</form:label>
						<form:input path="name" class="form-control"/>
						<form:errors path="name" class="text-danger"/>
					</div>
					
					<div class="form-group">
						<form:label path="email">E-mail:</form:label>
						<form:input type="email" path="email" class="form-control"/>
						<form:errors path="email" class="text-danger"/>
					</div>
					
					<div class="form-group">
						<form:label path="password">Password:</form:label>
						<form:password path="password" class="form-control"/>
						<form:errors path="password" class="text-danger"/>
					</div>
					
					<div class="form-group">
						<form:label path="confirm">Confirmación:</form:label>
						<form:password path="confirm" class="form-control"/>
						<form:errors path="confirm" class="text-danger"/>
					</div>
					<input type="submit" value="Registrarme" class="btn btn-primary">
				</form:form>
			</div>
			
			<div class="col-6">
				<h2>Inicia Sesión</h2>
				<form:form method="post" action="/login" modelAttribute="nuevoLogin">
					<div class="form-group">
						<form:label path="email">E-mail:</form:label>
						<form:input type="email" path="email" class="form-control"/>
						<form:errors path="email" class="text-danger"/>
					</div>
					
					<div class="form-group">
						<form:label path="password">Password:</form:label>
						<form:password path="password" class="form-control"/>
						<form:errors path="password" class="text-danger"/>
					</div>
					<input type="submit" value="Inicia Sesión" class="btn btn-primary">
				</form:form>
			</div>
			
		</div>
	</div>

</body>
</html>