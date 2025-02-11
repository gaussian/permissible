from django import template

register = template.Library()


@register.filter
def get_item(dictionary, key):
    return dictionary.get(key)


@register.simple_tag
def admin_change_url(obj):
    """Get the admin URL pattern for changing an object"""
    return f"admin:{obj._meta.app_label}_{obj._meta.model_name}_change"
