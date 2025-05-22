from django import forms
import ipaddress

def validate_ip_or_cidr(value):
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError:
        raise forms.ValidationError('Por favor, introduce una dirección IP o un rango CIDR válido (ej. 192.168.1.1 o 192.168.1.0/24).')

class IpBlockingForm(forms.Form):
    ip_address = forms.CharField(
        label='Dirección IP o Rango CIDR',
        max_length=45,
        validators=[validate_ip_or_cidr],
        widget=forms.TextInput(attrs={
            'placeholder': 'ej. 192.168.1.1 o 10.0.0.0/24',
            'class': 'block w-full pl-10 pr-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm placeholder-gray-400 dark:placeholder-gray-500 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-red-500 sm:text-sm transition duration-150 ease-in-out'
        })
    )
    action = forms.CharField(widget=forms.HiddenInput()) 