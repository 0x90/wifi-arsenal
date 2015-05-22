from django import template

register = template.Library()

@register.filter
def dot_colour(operator):
	d = 'blue'
	if 'Optus' in operator:
		d = 'yellow'
	if 'Vodafone' in operator:
		d = 'red'
	if 'Three' in operator:
		d = 'red'

	if 'CID:-1' in operator:
		return d+'LAC'
	
	return d+'Cell'

