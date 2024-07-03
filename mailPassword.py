""" import smtplib
import ssl


def mailid(admin, mail):
    port = 587
    smtp_server = "smtp.gmail.com"
    sender_email = "passmanagepadddu@gmail.com"
    receiver_email = mail
    password = "mail1234!project"
    message = f'''Subject: Your Request has been mailed.

        Your Admin Password is {admin}'''

    context = ssl.create_default_context()
    with smtplib.SMTP(smtp_server, port) as server:
        server.ehlo()
        server.starttls(context=context)
        server.ehlo()
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, message) """
