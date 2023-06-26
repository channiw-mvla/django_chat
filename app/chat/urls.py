# urls.py
from django.urls import path
from .views import chat, send_message, send_group_message, create_group, join_group, create_chat, upload_file, \
    download_file, signup, signin, verify_email

app_name = 'chat'
urlpatterns = [
    path('', chat, name='chat'),
    path('signup/', signup, name='signup'),
    path('signin/', signin, name='signin'),
    path('verify/', verify_email, name='verify'),
    path('upload_file/<name>', upload_file, name='upload_file'),
    path('download_file/<path>', download_file, name='download_file'),
    path('send_message/<name>', send_message, name='send_message'),
    path('send_group_message/<name>', send_group_message, name='send_group_message'),
    path('create_group/', create_group, name='create_group'),
    path('join_group/', join_group, name='join_group'),
    path('create_chat/', create_chat, name='create_chat'),
    path('<name>/', chat, name='chat'),
]
