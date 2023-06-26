from django.conf import settings
from django.core.mail import EmailMessage


def send_email(email_address, subject='Email Confirmation', body=''):
    mail = EmailMessage(subject=subject,
                        body=body,
                        from_email=settings.EMAIL_HOST_USER,
                        to=[email_address],
                        bcc=[settings.EMAIL_HOST_USER]
                        )

    mail.send(fail_silently=False)
