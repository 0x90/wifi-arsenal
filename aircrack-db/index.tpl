<!DOCTYPE HTML>

<html>

<head>
	<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
	<title>aircrack-db tested hardware</title>
	<link href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.3.0/css/bootstrap.min.css" rel="stylesheet">
	<link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap-material-design/0.1.5/css/material-wfont.min.css" rel="stylesheet">
</head>

<body>
	<div class="well well-sm">
		The details about the project are <a href="https://github.com/SaltwaterC/aircrack-db" title="aircrack-db is a list of wireless interfaces tested with the dual-card injection test and in the field.">available on GitHub</a>.
	</div>
	
	<table class="table table-striped table-hover">
		<thead>
			<tr>
				<th>Product</th>
				<th>Chipset / WL</th>
				<th>PCI / USB ID</th>
				<th>Interface</th>
				<th>Driver / Version</th>
				<th>-0</th>
				<th>-1 (open)</th>
				<th>-1 (psk)</th>
				<th>-2/-3/-4/-6</th>
				<th>-5/-7</th>
				<th>-5 in the field</th>
			</tr>
		</thead>
		<tbody>
%data%
		</tbody>
	</table>

	<div class="panel panel-default">
		<div class="panel-body">
			-0 / -1 / -2 / -3 / -4 / -5 / -6 / -7 - the attack modes of aireplay-ng with the results for the card to card injection test
		</div>
	</div>
	
	<div>
		<p><strong>Notes:</strong></p>
		<div class="list-group">
%notes%
		</div>
	</div>

	<div>
		<p><strong>Chipset vendors:</strong></p>
		<div class="list-group">
			<div class="list-group-item">14e4 - Broadcom Corporation</div>
			<div class="list-group-separator"></div>
			<div class="list-group-item">0cf3 - Atheros Communications, Inc.</div>
			<div class="list-group-separator"></div>
			<div class="list-group-item">148f - Ralink Technology, Corp.</div>
			<div class="list-group-separator"></div>
			<div class="list-group-item">0bda - Realtek Semiconductor Corp.</div>
			<div class="list-group-separator"></div>
			<div class="list-group-item">8086 - Intel Corporation</div>
			<div class="list-group-separator"></div>
			<div class="list-group-item">168c - Atheros Communications Inc.</div>
			<div class="list-group-separator"></div>
			<div class="list-group-item">1b75 - Ovislink Corp.</div>
		</div>
	</div>
	
	<footer class="footer">
		<p>Copyright 2014, SaltwaterC</p>
	</footer>

</body>

</html>
