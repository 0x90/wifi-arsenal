var VALUE = 0;

function numeric(value)
{ 
	if (value == parseInt(value))
	{ 
		return value; 
	}
	else
	{ 
		var result = value.charCodeAt(0) - 55;
		return result; 
	}

}

function toHex(d)
{ 
	var r = d % 16;
	var result;
	if (d-r == 0)
		result = toChar(r);
	else
		result = toHex( (d-r)/16 ) + toChar(r);

	return result; 
}

function toChar(n)
{ 
	alpha = "0123456789ABCDEF"; 
	return alpha.charAt(n); 
}

function Pad(n, totalDigits)
{ 
	n = n.toString(); 
	var pd = ; 
	if (totalDigits > n.length)
	{ 
		for (i=0; i < (totalDigits-n.length); i++)
		{ 
			pd += '0'; 
		}
	}
	return pd + n.toString(); 
}

function calcit()
{ 
	var ESSID = ""; 
	var i = 0; 
	ESSID = document.getElementById('essid').value; 
	if (ESSID == "")
	{ 
		document.getElementById('key').value = 'error'; 
		document.getElementById('key2').value = 'error'; 
	}
	else
	{ 
		ESSID = ESSID.toUpperCase(); 
		for (i = 0; i < 5; i++)
		{ 
			VALUE = VALUE + (numeric(ESSID.charAt(i)) * Math.pow(36,i)); 
		}
	
		document.getElementById('key').value = '1801' + Pad(toHex(VALUE),6); 
		document.getElementById('key2').value = '1F90' + Pad(toHex(VALUE),6); 
		document.getElementById('essid').value = ESSID; VALUE=0; 
	}
}