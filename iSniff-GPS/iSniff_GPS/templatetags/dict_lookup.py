from django import template

register = template.Library()

@register.filter
def key(d, key):
    return d[key]
