from django import forms
from .models import Account

class RegistrationForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput(attrs={
        'placeholder': 'Enter Password',
    }))
    confirm_password = forms.CharField(widget=forms.PasswordInput(attrs={
        'placeholder': 'Confirm Password',
        
    }))

    class Meta:
        model = Account 
        fields = ['firstName', 'lastName', 'email', 'phoneNum', 'password']

    def clean(self): 
        cleaned_data = super(RegistrationForm, self).clean()
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')

        if password != confirm_password:
            raise forms.ValidationError(
                "Email/Password is not valid - please try again."
            )

    def __init__(self, *args, **kwargs):
        super(RegistrationForm, self).__init__(*args, **kwargs)
        self.fields['firstName'].widget.attrs['placeholder'] = 'Enter First Name'
        self.fields['lastName'].widget.attrs['placeholder'] = 'Enter Last Name'
        self.fields['phoneNum'].widget.attrs['placeholder'] = 'Enter Phone Number'
        self.fields['email'].widget.attrs['placeholder'] = 'Enter Email'
        for field in self.fields: 
            self.fields[field].widget.attrs['class'] = 'form-control'
