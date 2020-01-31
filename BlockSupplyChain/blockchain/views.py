from django.shortcuts import render, redirect, HttpResponseRedirect, HttpResponse
from django.contrib.auth.models import auth
from django.contrib import messages
from django.urls import reverse
from django.contrib.auth import get_user_model
import socket
from .utils import *
from blockchain import utils

User = get_user_model()
# Create your views here.

User.objects.all().update(node_address='')


def register(request):
    print(request.user)
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        password1 = request.POST['password1']
        password2 = request.POST['password2']

        if password1 == password2:
            if User.objects.filter(username=username).exists():
                messages.info(request, 'Username Taken')
                return HttpResponseRedirect(reverse('register'))
            elif User.objects.filter(email=email).exists():
                messages.info(request, 'Email Taken')
                return HttpResponseRedirect(reverse('register'))
            else:
                user = User.objects.create_user(
                    username=username, email=email, password=password1)
                user.save()
        else:
            messages.info(request, 'Password not matching')
            return HttpResponseRedirect(reverse('register'))
        return redirect('../')

    else:
        return render(request, 'join.html')


def user_login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        user = auth.authenticate(username=username, password=password)

        if user is not None:
            auth.login(request, user)
            host_name = socket.gethostname()
            host_ip = socket.gethostbyname(host_name)
            user.node_address = "http://" + host_ip + \
                ":" + request.META['SERVER_PORT'] + "/"
            user.save()
            print(user.node_address)
            data = connecting_logged_in_users(request)
            json_formatted_str = json.dumps(data, indent=2)

            return HttpResponse(json_formatted_str)
        else:
            messages.info(request, 'Username or password incorrect')
            return redirect('login')
    else:
        return render(request, 'login.html')


def logout(request):
    utils.disconnecting(request)
    auth.logout(request)
    # connecting_logged_in_users(request)
    return redirect(reverse('login'))
