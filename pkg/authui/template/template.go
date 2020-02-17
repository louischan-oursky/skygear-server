package template

import (
	"github.com/skygeario/skygear-server/pkg/core/config"
	"github.com/skygeario/skygear-server/pkg/core/template"
)

const (
	TemplateItemTypeAuthUIAuthorizeHTML config.TemplateItemType = "auth_ui_authorize.html"
)

// TODO(authui): Apply autoprefixer on CSS and externalize it.
// TODO(authui): Introduce a build pipeline to upload asset.

var TemplateAuthUIAuthorizeHTML = template.Spec{
	Type:   TemplateItemTypeAuthUIAuthorizeHTML,
	IsHTML: true,
	Default: `<!DOCTYPE html>
<html>
<head>
<title>{{ .appname }}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
html, body {
	margin: 0;
	padding: 0;
	min-height: 100vh;
}

*, *::before, *::after {
	box-sizing: border-box;
}

.primary-txt {}

.secondary-txt {}

.btn {
	-webkit-appearance: none;
	border: none;
	font-size: 14px;
}

.input {
	border: none;
	border-radius: 0;
	font-size: 14px;
	border-bottom: solid 1px #a19f9d;
	height: 32px;
}

.input:focus, .btn:focus {
	outline: none;
}

.input:focus {
	border-bottom: solid 1px #166bef;
}

.select {
	-webkit-appearance: none;
	background-color: white;
	height: 32px;
	border-bottom: solid 1px #a19f9d;
	/* TODO(authui): <select> arrow */
	padding: 0 28px 0 8px;
}

.text-input {
	padding: 0 8px;
}

.btn:hover {
	cursor: pointer;
}

.primary-btn {
	height: 32px;
	border-radius: 2px;
	color: white;
	padding: 0 20px;
	background-color: #166bef;
}

.secondary-btn {}

.anchor {
	text-decoration: none;
	font-size: 12px;
}

.anchor:link, .anchor:visited {
	color: #166bef;
}

.page {
	background-color: white;
}

.content {
	background-color: white;
}

.logo {
	height: 139px;
	background-position: center;
	background-size: cover;
	background-repeat: no-repeat;
}

.skygear-logo {
	height: 80px;
	background-position: center;
	background-repeat: no-repeat;
}

@media (min-width: 320px) {
}

@media (min-width: 1025px) {
	.page {
		display: flex;
		flex-direction: row;
		justify-content: center;
		align-items: flex-start;
	}
	.content {
		margin: 52px 0 0 0;
		min-width: 416px;
		border-radius: 2px;
		box-shadow: 0 0.3px 0.9px 0 rgba(0, 0, 0, 0.11), 0 1.6px 3.6px 0 rgba(0, 0, 0, 0.13);
	}
}

.authorize-loginid-links {
	display: flex;
	flex-direction: column;
	padding: 10px 20px;
}

.authorize-loginid-links .anchor {
	display: block;
}

.authorize-loginid-form {
	display: flex;
	flex-direction: row;
	padding: 10px;
}

.authorize-loginid-form [name="x_login_id"] {
	flex: 1;
	margin: 0 15px 0 10px;
}

.authorize-loginid-form [type="submit"] {
	margin: 0 10px 0 15px;
}

.authorize-loginid-form [name="x_calling_code"] {
	margin: 0 3px 0 10px;
}

.authorize-loginid-form [name="x_nation_number"] {
	flex: 1;
	margin: 0 10px 0 3px;
}

</style>
</head>
<body class="page">
	<div class="content">
		<div class="logo" style="background-image: url('{{ .logo_url }}')"></div>
		<form class="authorize-loginid-form" method="post">
			<input type="hidden" name="scope" value="{{ .scope }}">
			<input type="hidden" name="response_type" value="{{ .response_type }}">
			<input type="hidden" name="client_id" value="{{ .client_id }}">
			<input type="hidden" name="redirect_uri" value="{{ .redirect_uri }}">
			<input type="hidden" name="code_challenge_method" value="{{ .code_challenge_method }}">
			<input type="hidden" name="code_challenge" value="{{ .code_challenge }}">

			<input type="hidden" name="x_login_id_type" value="{{ .x_login_id_type }}">

			<input type="hidden" name="x_step" value="input_login_id">
			{{ if (and .x_login_id_type (eq .x_login_id_type "phone") .x_login_id_type_has_phone) }}
				<select class="input select" name="x_calling_code">
					<option value="">Code</option>
					{{ range .x_calling_codes }}
					<option value="+{{ . }}">+{{ . }}</option>
					{{ end }}
				</select>
				<input class="input text-input" type="tel" name="x_nation_number" placeholder="Phone number">
			{{ end }}
			{{ if (and .x_login_id_type (not (eq .x_login_id_type "phone")) .x_login_id_type_has_text) }}
				<input class="input text-input" type="email" name="x_login_id" placeholder="Email or Username">
			{{ end }}

			{{ if (or .x_login_id_type_has_phone .x_login_id_type_has_text) }}
				<button class="btn primary-btn" type="submit" name="_">Login</button>
			{{ end }}
		</form>
		<div class="authorize-loginid-links">
		{{ if (and .x_login_id_type (eq .x_login_id_type "phone") .x_login_id_type_has_text) }}
			<a class="anchor" href="{{ .x_use_text_url }}">Use an email or username instead</a>
		{{ end }}
		{{ if (and .x_login_id_type (not (eq .x_login_id_type "phone")) .x_login_id_type_has_phone) }}
			<a class="anchor" href="{{ .x_use_phone_url }}">Use a phone number instead</a>
		{{ end }}
		</div>

		{{ if .error }}
			{{ if eq .error.reason "ValidationFailed" }}
			<ul>
			{{ range .error.info.causes }}
			<li>{{ .message }}</li>
			{{ end }}
			</ul>
			{{ else }}
			<ul>
			<li>{{ .error.message }}</li>
			</ul>
			{{ end }}
		{{ end }}

		<div class="skygear-logo" style="background-image: url('{{ .skygear_logo_url }}')"></div>
	</div>
</body>
</html>
`,
}
