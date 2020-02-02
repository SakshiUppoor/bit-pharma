from django.shortcuts import render, redirect, HttpResponseRedirect, HttpResponse
from django.contrib.auth.models import auth
from django.contrib import messages
from django.urls import reverse
from django.contrib.auth import get_user_model
import socket
from .utils import *
from blockchain import utils
from uuid import uuid4
from django.contrib.auth.decorators import user_passes_test
import random
import pyqrcode
from PIL import Image
from pyzbar.pyzbar import decode

User = get_user_model()
# Create your views here.

User.objects.all().update(node_address='')


def sendOtp(first_name, otp, phone):
    url = "https://www.fast2sms.com/dev/bulk"
    payload = f"sender_id=FSTSMS&message=Hi {first_name}! Your verification code is : {otp} &language=english&route=p&numbers={phone}"
    headers = {
        'authorization': "xmSHAJhecCogOEzUudp1vMPl7w2a6D53RIWt89X0kVLFnYNZfrFQfLkclToD62CNMOpdGSvj1X98Pa4K",
        'Content-Type': "application/x-www-form-urlencoded",
        'Cache-Control': "no-cache",
    }
    requests.request("POST", url, data=payload, headers=headers)


def verifyOtp(request):
    if request.user.otp == request.POST['otp']:
        request.user.is_no_verified = True
        request.user.save()
        return redirect('add_drug.html')
    else:
        return redirect('track.html')


def home_handle(request):
    if request.method == 'POST':
        otp = request.POST['otp']
        print(otp)
        print(request.user.otp)
        if str(otp) == str(request.user.otp):
            print("Here!!1")
            request.user.is_no_verified = True
            request.user.save()
    return render(request, 'home.html')


# uuid typeOf phone
def register(request):
    print(request.user)
    if request.method == 'POST':
        first_name = request.POST['organization']
        email = request.POST['email']
        phone = request.POST['phone']
        password1 = request.POST['password1']
        password2 = request.POST['password2']

        if password1 == password2:
            if User.objects.filter(first_name=first_name).exists():
                messages.info(request, 'Organization Name Exists')
                return HttpResponseRedirect(reverse('register'))
            elif User.objects.filter(email=email).exists():
                messages.info(request, 'Email Taken')
                return HttpResponseRedirect(reverse('register'))
            else:
                otp = random.randrange(1000, 9999)
                user = User.objects.create_user(
                    first_name=first_name, email=email, password=password1, username=str(uuid4()), otp=otp)
                sendOtp(first_name, otp, phone)
                user.save()
                auth.login(request, user)
                host_name = socket.gethostname()
                host_ip = socket.gethostbyname(host_name)
                user.node_address = "http://" + host_ip + \
                    ":" + request.META['SERVER_PORT'] + "/"
                user.save()
                url = "http://" + host_ip + ":8000/get_chain"
                connecting_logged_in_users(request)
                response = json.loads(requests.get(url).text)["chain"]
                print(response)
                blockchain.chain = response

                url = "http://" + host_ip + ":8000/get_univ_drugs/"
                response = json.loads(requests.get(url).text)["drugs"]
                print(response)
                blockchain.univ_drugs = response

                inv1 = set()
                for d in blockchain.inv_drugs:
                    inv1.add(d["drug_id"])

                inv2 = set()

                for block in blockchain.chain:
                    for t in block["transactions"]:
                        if t["receiver"] == user.username:
                            inv2.add(t["drug_id"])
                        if t["sender"] == user.username:
                            inv2.discard(t["drug_id"])

                for d in inv2:
                    if d not in inv1:
                        blockchain.inv_drugs.append(get_drug_details(d))

                return HttpResponseRedirect(reverse('home'))
        else:
            messages.info(request, 'Password not matching')
            return HttpResponseRedirect(reverse('register'))
        return redirect('../')

    else:
        return render(request, 'join.html')


def user_login(request):
    if request.method == 'POST':
        username = request.POST['organization']
        password = request.POST['password']

        user = auth.authenticate(username=username, password=password)

        if user is not None:
            auth.login(request, user)
            host_name = socket.gethostname()
            host_ip = socket.gethostbyname(host_name)
            user.node_address = "http://" + host_ip + \
                ":" + request.META['SERVER_PORT'] + "/"
            user.save()
            url = "http://" + host_ip + ":8000/get_chain"
            connecting_logged_in_users(request)
            response = json.loads(requests.get(url).text)["chain"]
            print(response)
            blockchain.chain = response

            url = "http://" + host_ip + ":8000/get_univ_drugs/"
            response = json.loads(requests.get(url).text)["drugs"]
            print(response)
            blockchain.univ_drugs = response

            inv1 = set()
            for d in blockchain.inv_drugs:
                inv1.add(d["drug_id"])

            inv2 = set()

            for block in blockchain.chain:
                for t in block["transactions"]:
                    if t["receiver"] == user.username:
                        inv2.add(t["drug_id"])
                    if t["sender"] == user.username:
                        inv2.discard(t["drug_id"])

            for d in inv2:
                if d not in inv1:
                    blockchain.inv_drugs.append(get_drug_details(d))

            return HttpResponseRedirect(reverse('home'))
            # if user.is_no_verified==False:
            #     return HttpResponseRedirect(reverse('verify'))
            # else:
            #     return HttpResponseRedirect(reverse('join'))

        else:
            messages.info(request, 'Username or password incorrects')
            return redirect('login')
    else:
        return render(request, 'login.html')


def get_drug_details(d):
    for drug in blockchain.univ_drugs:
        if drug["drug_id"] == d:
            return drug


def logout(request):
    utils.disconnecting(request)
    auth.logout(request)
    # connecting_logged_in_users(request)
    return redirect(reverse('login'))


def create_drug(request):
    data = requests.get(request.user.node_address+"get_nodes/")
    print(json.loads(data.text))
    json_obj = json.loads(data.text)
    data = requests.get(request.user.node_address+"get_nodes/")
    print(json.loads(data.text))
    json_obj = json.loads(data.text)
    if request.method == 'POST':
        drug_name = request.POST['drug_name']
        drug_id = str(uuid4())
        dom = request.POST['dom']
        doe = request.POST['doe']
        '''
        chem_list = request.POST['chem_list'].split(',')
        chem_composition = {}
        for chem in chem_list:
            name = chem.split(':')[0]
            p = chem.split(':')[1]
            chem_composition[name] = p
        '''
        new_drug = {
            "drug_name": drug_name,
            "drug_id": drug_id,
            "dom": dom,
            "doe": doe,
            # "chemicals": chem_composition,
        }
        host_name = socket.gethostname()
        host_ip = socket.gethostbyname(host_name)
        x = "http://" + host_ip + \
            ":" + request.META['SERVER_PORT'] + "/track/" + drug_id

        print(x)
        big_code = pyqrcode.create(x)
        big_code.png(drug_id + '.png')
        big_code.show()
        """
        for f in request.FILES.getlist('files'):
            print(f)"""
        #add_to_someones_inv(request.user, new_drug)
        blockchain.inv_drugs.append(new_drug)
        blockchain.univ_drugs.append(new_drug)
        for node in json_obj["nodes"]:
            url = 'http://' + node + '/update_univ/'
            data = '{"drugs": [{'
            for d in new_drug:
                data += '"' + d + '": "' + new_drug[d] + '",'
            data = data[:-1]
            data += '}]}'
            print(data)
            requests.post(url, data=data)
        return HttpResponseRedirect(reverse('inventory'))
    context = {
        'network': json_obj["nodes"],
    }
    return render(request, "add_drug.html")


def transfer(request):
    data = requests.get(request.user.node_address+"get_nodes/")
    print(json.loads(data.text))
    json_obj = json.loads(data.text)
    if request.method == 'POST':
        receiver = request.POST['receiver']
        drugs = request.POST.getlist('drugs[]')
        print("DRUGS=", drugs)
        for drug in drugs:
            data = '{"sender":"' + request.user.username + \
                '","receiver":"' + receiver + '","drug_id":"' + drug + '"}'
            u = request.user.node_address
            url = u + 'add_transaction/'
            print("URL=", url)
            print("DATA=", data)
            requests.post(url, data=data)
            blockchain.inv_drugs.remove(get_drug_details(drug))
        requests.get(request.user.node_address + 'mine_block/')
        data = requests.get(
            request.user.node_address+'is_valid/')
        response = json.loads(data.text)
        if response["message"] == "All good. The Blockchain is valid.":
            for node in blockchain.nodes:
                url = 'http://' + node + '/'
                if url != request.user.node_address:
                    url += 'add_transaction/'
                    for drug in drugs:
                        data = '{"sender":"' + request.user.username + \
                            '","receiver":"' + receiver + '","drug_id":"' + drug + '"}'
                        print("URL=", url)
                        print("DATA=", data)
                        requests.post(url, data=data)
                    user = User.objects.get(username=receiver)
                    utils.add_to_someones_inv(user, blockchain.univ_drugs)
                    requests.get('http://' + node + '/mine_block/')
        utils.replace_chain_in_all_nodes()
        return HttpResponseRedirect(reverse('transactions'))

    drugs = blockchain.inv_drugs
    context = {
        'network': json_obj["nodes"],
        'l': drugs,
    }
    return render(request, 'transfer.html', context)


def home(request):
    data = requests.get(request.user.node_address+"get_nodes/")
    print(json.loads(data.text))
    json_obj = json.loads(data.text)
    data = requests.get(request.user.node_address+"get_nodes/")
    print(json.loads(data.text))
    json_obj = json.loads(data.text)

    context = {
        'network': json_obj["nodes"],
        'response': blockchain.chain,
    }
    return render(request, 'home.html', context)


def transactions(request):
    data = requests.get(request.user.node_address+"get_nodes/")
    print(json.loads(data.text))
    json_obj = json.loads(data.text)
    sent = []
    received = []
    for entry in blockchain.chain:
        for transaction in entry["transactions"]:
            if str(transaction["receiver"]) == request.user.username:
                received.append(transaction)
            elif str(transaction["sender"]) == request.user.username:
                sent.append(transaction)
    print(sent)
    print(received)
    context = {
        'network': json_obj["nodes"],
        'sent': sent,
        'received': received,
    }
    return render(request, 'transactions.html', context)
    # print(blockchain.chain)


def inventory(request):
    data = requests.get(request.user.node_address+"get_nodes/")
    print(json.loads(data.text))
    json_obj = json.loads(data.text)
    drugs = blockchain.inv_drugs
    context = {
        'network': json_obj["nodes"],
        'l': drugs,
    }
    return render(request, 'inventory.html', context)


def reports(request):
    data = requests.get(request.user.node_address+"get_nodes/")
    print(json.loads(data.text))
    json_obj = json.loads(data.text)
    context = {
        'network': json_obj["nodes"],
    }
    return render(request, 'reports.html',
                  context
                  )

def fp(request):
    return render(request, "fp.html")