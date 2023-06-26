from django.contrib import admin
from . import models

admin.site.register(models.User)
admin.site.register(models.Chat)
admin.site.register(models.EmailToken)
