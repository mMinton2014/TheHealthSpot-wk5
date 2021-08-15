from typing import overload
from accounts.forms import RegistrationForm
from django.shortcuts import redirect, render
from .forms import RegistrationForm
from .models import Account
from carts.models import Cart, CartItem
from django.contrib import messages, auth
from django.contrib.auth.decorators import login_required

#verification email 
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes 
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMessage
from django.http import HttpResponse

from carts.views import _cart_id
import requests


def register(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            firstName = form.cleaned_data['firstName']
            lastName = form.cleaned_data['lastName']
            phoneNum = form.cleaned_data['phoneNum']
            email = form.cleaned_data['email']
            password= form.cleaned_data['password']
            username= email.split("@")[0]
            #matches with create user
            user = Account.objects.create_user(firstName=firstName, lastName=lastName, email=email, username=username, password=password)
            user.phoneNum = phoneNum
            user.save()

            #user activiation 
            current_site = get_current_site(request)
            mail_subject = 'Please activate your account'
            message = render_to_string('accounts/account_verification_email.html', {
                'user': user,
                'domain': current_site,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user),
            })
            to_email = email
            send_email = EmailMessage(mail_subject, message, to=[to_email])
            send_email.send()
            #messages.success(request, 'Registration successful. Please check your email for your activation link. ')
            return redirect('/accounts/login/?command=verification&email='+email)
    else: 
        form = RegistrationForm()

    context = {
        'form': form,
    }
    return render(request, 'accounts/register.html', context)


def login(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']

        user = auth.authenticate(email=email, password=password)
        if user is not None:
            try:
                cart = Cart.objects.get(cart_id=_cart_id(request))
                is_cart_item_exists = CartItem.objects.filter(cart=cart).exists()
                if is_cart_item_exists:
                    cart_item = CartItem.objects.filter(cart=cart)

                    #gets product variations by the card id
                    product_variation = []
                    for item in cart_item: 
                        variation = item.variations.all()
                        product_variation.append(list(variation))

                    #get cart items from the user to access their variations
                    cart_item = CartItem.objects.filter(user=user) 
                    existing_variations_list=[]
                    id = []
                    for item in cart_item:
                        existing_variation = item.variations.all()
                        existing_variations_list.append(list(existing_variation))
                        id.append(item.id)

                    for prd in product_variation:
                        if prd in existing_variations_list:
                            index = existing_variations_list.index(prd)
                            item_id = id[index]
                            item = CartItem.objects.get(id=item_id)
                            item.quantity += 1
                            item.user = user
                            item.save()
                        else: 
                            cart_item = CartItem.objects.filter(cart=cart)
                            for item in cart_item:
                                item.user = user
                                item.save()
            except:
                pass
            auth.login(request, user)
            messages.success(request, 'You are now logged in.')
            url = request.META.get('HTTP_REFERER')
            try:
                query = requests.utils.urlparse(url).query
                params = dict(x.split('=') for x in query.split('&'))
                if 'next' in params:
                    nextPage = params['next']
                    return redirect(nextPage)
            except: 
                return redirect('dashboard')
        else: 
            messages.error(request, 'invalid loggin creditials')
            return redirect('login')

    return render(request, 'accounts/login.html')



@login_required(login_url= 'login')
def logout(request):
    auth.logout(request)
    messages.success(request, 'You are logged out!')
    return redirect('login')
    #return render(request, 'accounts/logout.html')

def activate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = Account._default_manager.get(pk=uid)
    except(TypeError, ValueError, OverflowError, Account.DoesNotExist):
        user = None
    
    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, 'Congratulations! Your account has been actived. ') 
        return redirect('login')
    else: 
        messages.error(request, 'Invalid activation link.')
        return redirect('register')

@login_required(login_url= 'login')
def dashboard(request):
    return render(request, 'accounts/dashboard.html')


def forgotPassword(request):
    if request.method == 'POST':
        email = request.POST['email']
        if Account.objects.filter(email=email).exists():
            user = Account.objects.get(email__iexact=email)

            #reset password email  
            current_site = get_current_site(request)
            mail_subject = 'Your new password'
            message = render_to_string('accounts/reset_password_email.html', {
                'user': user,
                'domain': current_site,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user),
            })
            to_email = email
            send_email = EmailMessage(mail_subject, message, to=[to_email])
            send_email.send()

            messages.success(request, 'The password reset email has been sent to your email address.')
            return redirect('login')

        else: 
            messages.error(request, 'Account for the email you entered does not exist')
            return redirect('forgotPassword')
    return render(request, 'accounts/forgotPassword.html')


def resetpassword_validate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = Account._default_manager.get(pk=uid)
    except(TypeError, ValueError, OverflowError, Account.DoesNotExist):
        user = None
    
    if user is not None and default_token_generator.check_token(user, token):
        request.session['uid'] = uid
        messages.success(request, 'Please reset your password.')
        return redirect('resetPassword')
    else: 
        messages.error(request, 'This link is now expired.')
        return redirect('login')


def resetPassword(request):
    if request.method == 'POST':
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']

        if password == confirm_password:
            uid = request.session.get('uid')
            user = Account.objects.get(pk=uid)
            user.set_password(password)
            user.save()
            messages.success(request, 'Password reset was successful. Please login. ')
            return redirect('login')

        else: 
            messages.error(request, 'Passwords do not match.')
            return redirect('resetPassword')
    else: 
        return render(request, 'accounts/resetPassword.html')