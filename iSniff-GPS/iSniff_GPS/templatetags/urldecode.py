from django import template
from urllib import unquote

register = template.Library()

@register.filter
def urldecode(value):
    return unquote(value)
