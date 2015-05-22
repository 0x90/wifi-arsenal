#!/usr/bin/env node

var fs = require('fs');

var db = require('./db.json');
var tpl = fs.readFileSync('./index.tpl').toString();

var i, j, product, split, row, rows = [], cell, cells, notes = [], notes_html = '', index;

for (i = 0; i < db.length; i++) {
	product = db[i];
	row = '\t\t\t<tr>\n';
	cells = '';
	for (j = 0; j < product.length; j++) {
		cell = product[j];
		
		if (j == 0) {
			split = cell.split(/;/);
			cell = split[0];
			if (split[1]) {
				cell += ' <a href="#note-' + (notes.length + 1) + '"><sup>' + (notes.length + 1) + '</sup></a>';
				notes.push(split[1].trim());
			}
		}
		
		if (cell.match(/(?:pci|usb):[0-9a-f]{4}:[0-9a-f]{4}/)) {
			split = cell.split(/:/);
			if (split[0] === 'pci') {
				cell = '<a href="http://pci-ids.ucw.cz/read/PC/' + split[1] + '/' + split[2] + '">' + split[1] + ':' + split[2] + '</a>';
			}
			
			if (split[0] === 'usb') {
				cell = '<a href="https://usb-ids.gowdy.us/read/UD/' + split[1] + '/' + split[2] + '">' + split[1] + ':' + split[2] + '</a>';
			}
		}
		
		if (cell === 'OK' || cell === 'Yes') {
			cell = '<span class="label label-success">' + cell + '</span>';
		}
		
		if (cell === 'Failed' || cell === 'No') {
			cell = '<span class="label label-danger">' + cell + '</span>';
		}
		
		if (cell === 'Untested') {
			cell = '<span class="label label-warning">' + cell + '</span>';
		}
		
		cells += '\t\t\t\t<td>' + cell + '</td>\n';
	}
	row += cells + '\t\t\t</tr>';
	rows.push(row);
}

index = tpl.replace(/%data%/, rows.join('\n'));

for (i = 0; i < notes.length; i++) {
	notes_html += '\t\t\t<div class="list-group-item"><a name="note-' + (i + 1) + '"></a>' + (i + 1) + ': ' + notes[i] + '</div>';
	if (i !== notes.length - 1) {
		notes_html += '\n\t\t\t<div class="list-group-separator"></div>\n';
	}
}

index = index.replace(/%notes%/, notes_html);

fs.writeFileSync('../db/index.html', index);
console.log('Written the data to ../db/index.html');
