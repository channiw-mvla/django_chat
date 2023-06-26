from django.shortcuts import render, redirect
from django.db.models import Q
from django.core.files.storage import FileSystemStorage
from django.http import HttpResponse
from django.contrib.auth import authenticate, login
from django.conf import settings
from django.shortcuts import get_object_or_404

from .models import Chat, User, GroupChat, Group, EmailToken
from .email_utils import send_email
from datetime import datetime
from uuid import uuid4

import os


def get_chat_data(user_chat, self):
    filename = ''
    if 'http' in user_chat.message:
        filename = user_chat.message.split("/")[-1]

    return {"message": user_chat.message,
            "date": user_chat.date.strftime("%d %b %y"),
            "time": user_chat.date.strftime("%I:%M %p"),
            "self": self,
            "fileName": filename}


def get_group_chat_data(group_chat):
    filename = ''
    if 'http' in group_chat.message:
        filename = group_chat.message.split("/")[-1]

    return {"message": group_chat.message,
            "date": group_chat.date.strftime("%d %b %y"),
            "time": group_chat.date.strftime("%I:%M %p"),
            "sender": group_chat.sender_user.username,
            "fileName": filename}


def get_user_chats(user, name):

    user_chats = Chat.objects.filter(Q(sender_user=user) | Q(receiver_user=user)).order_by('date')
    user_chats_dict = {}
    for user_chat in user_chats:
        if user_chat.date is None:
            user_chat.date = datetime.utcnow()

        if user.id == user_chat.receiver_user.id:
            if user_chats_dict.get(user_chat.sender_user.username, None) is None:
                user_chats_dict[user_chat.sender_user.username] = {"messages": [],
                                                                   "name": user_chat.sender_user.username}

            user_chats_dict[user_chat.sender_user.username]["messages"].append(get_chat_data(user_chat, False))
        else:
            if user_chats_dict.get(user_chat.receiver_user.username, None) is None:
                user_chats_dict[user_chat.receiver_user.username] = {"messages": [],
                                                                     "name": user_chat.receiver_user.username}

            user_chats_dict[user_chat.receiver_user.username]["messages"].append(get_chat_data(user_chat, True))

    if name:
        user_chats_dict["user"] = user_chats_dict.get(name, {})

    return user_chats_dict


def get_group_chats(user, key):
    group = user.group.filter(key=key).values('id').first()
    if group is None:
        return {}

    group_id = group['id']
    group_chats = GroupChat.objects.filter(group_id=group_id).order_by('date')
    group_chats_list = []
    for group_chat in group_chats:
        if group_chat.date is None:
            group_chat.date = datetime.utcnow()
            group_chat.save()

        group_chats_list.append(get_group_chat_data(group_chat))

    return group_chats_list


def chat(request, name=None):
    template_name = "chat.html"
    if not request.user.is_authenticated:
        return redirect('/')

    user_chats = get_user_chats(request.user, name)
    group_chats = get_group_chats(request.user, name)
    all_users = User.objects.filter(~Q(id=request.user.id) & Q(is_staff=False)).all().values('username')
    return render(request, template_name, context={"data": user_chats,
                                                   "users": all_users,
                                                   "groups": request.user.group.all().values('name', 'key'),
                                                   "group_chats": {"messages": group_chats,
                                                                   "key": name if user_chats.get('user', {}) == {} else None}})


def send_message(request, name=None):
    new_file = request.FILES

    if name is None:
        return redirect('/chat')

    receiver_user = User.objects.filter(username=name).first()
    if request.FILES.get('file', None) is not None:
        new_file = request.FILES['file']
        fs = FileSystemStorage()
        filename = fs.save(f'files/{new_file.name}', new_file)
        new_chat = Chat(message=f"http://localhost:8000/chat/download_file/{new_file.name}",
                        sender_user=request.user,
                        receiver_user=receiver_user,
                        date=datetime.utcnow())
        new_chat.save()

    message = request.POST.get('message')
    if message.strip() == '':
        return redirect(f'/chat/{name}')

    new_chat = Chat(message=message,
                    sender_user=request.user,
                    receiver_user=receiver_user,
                    date=datetime.utcnow())
    new_chat.save()

    return redirect(f'/chat/{name}')


def send_group_message(request, name=None):
    if name is None:
        return redirect('/chat')

    group = Group.objects.filter(key=name).first()

    if request.FILES.get('file', None) is not None:
        new_file = request.FILES['file']
        fs = FileSystemStorage()
        filename = fs.save(f'files/{new_file.name}', new_file)
        new_chat = GroupChat(message=f"http://localhost:8000/chat/download_file/{new_file.name}",
                             sender_user=request.user,
                             date=datetime.utcnow(),
                             group=group)
        new_chat.save()

    message = request.POST.get('message')
    if message.strip() == '':
        return redirect(f'/chat/{name}')

    new_chat = GroupChat(message=message,
                         date=datetime.utcnow(),
                         sender_user=request.user,
                         group=group)

    new_chat.save()

    return redirect(f'/chat/{name}')


def create_group(request):

    user = request.user
    group_name = request.POST.get('gname')
    new_group = Group(name=group_name)
    new_group.save()

    user.group.add(new_group)
    user.save()

    return redirect(f'/chat/{new_group.key}')


def join_group(request):

    user = request.user
    key = request.POST.get('code')
    group = Group.objects.filter(key=key).first()
    if group is None:
        return redirect(f'/chat')

    user.group.add(group)
    user.save()

    return redirect(f'/chat/{group.key}')


def create_chat(request):

    username = request.POST.get('username')
    user = User.objects.filter(username=username).first()
    if user is None:
        return redirect(f'/chat')

    new_chat = Chat(message=request.POST.get('message'),
                    sender_user=request.user,
                    receiver_user=user,
                    date=datetime.utcnow())
    new_chat.save()

    return redirect(f'/chat/{username}')


def upload_file(request, name=None):
    if request.method == 'POST' and request.FILES['file']:
        new_file = request.FILES['file']
        fs = FileSystemStorage()
        fs.save(f'files/{new_file.name}', new_file)

        return redirect(f'/chat/{name}')

    return redirect(f'/chat')


def download_file(request, path):
    file_path = os.path.join('files', path)
    if os.path.exists(file_path):
        with open(file_path, 'rb') as fh:
            response = HttpResponse(fh.read(), content_type="application/vnd.ms-excel")
            response['Content-Disposition'] = 'inline; filename=' + os.path.basename(file_path)
            return response

    return redirect(f'/chat')


def signup(request):
    template_name = "signup.html"
    if request.method == "POST":
        email = request.POST.get('email')
        username = request.POST.get('username')
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        password = request.POST.get('password')
        try:
            user = User.objects.create_user(email=email,
                                            username=username,
                                            first_name=first_name,
                                            last_name=last_name,
                                            password=password,
                                            auth_provider=User.EMAIL)
            if not user.is_active:
                rand_token = uuid4()
                EmailToken(user=user, token=rand_token).save()
                send_email(email_address=user.email,
                           body=settings.ACTIVATION_BODY.format(name=user.first_name,
                                                                url=f"{settings.DOMAIN}/chat/verify?token={rand_token}")
                           )



        except Exception as exc:
            print(exc)
            return redirect(f'/chat/signup')

        if user is not None:
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')

        return redirect(f'/chat')

    return render(request, template_name)


def signin(request):

    email = request.POST.get('email')
    password = request.POST.get('password')
    user = authenticate(request, username=email, password=password)
    if user is not None:
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
    return redirect('/chat')


def verify_email(request):

    token = request.GET.get('token')
    email_token = get_object_or_404(EmailToken, token=token, is_verified=False)
    email_token.is_verified = True
    email_token.save()

    user = email_token.user
    user.is_active = True
    user.save()
    if user is not None:
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')

    return redirect('/chat')
