import json
import logging
import re
import smtplib
import subprocess
from email.mime.text import MIMEText

import boto3
import requests
from django.core.exceptions import ValidationError
from django.core.validators import validate_email

# Set up logging
logger = logging.getLogger(__name__)


# Custom Exceptions
class AmazonSNSFailed(Exception):
    pass


class AmazonSNSValidateFailed(Exception):
    pass


class EmailSendFailed(Exception):
    pass


class EmailValidateFailed(Exception):
    pass


class SignalFailed(Exception):
    pass


class SignalValidateFailed(Exception):
    pass


class SlackValidateFailed(Exception):
    pass


class SlackSendFailed(Exception):
    pass


class AmazonSNS:
    def __init__(self, options):
        self.msg_template = options['msg_template']
        self.aws_key = options['aws_key']
        self.aws_secret = options['aws_secret']
        self.aws_region = options['aws_region']
        self.sender_id = options['sender_id']
        self.ldap_attribute_name = options.get('ldap_attribute_name', 'telephonenumber')

    def __filter_phones(self, phones):
        phone_regexp = re.compile(r'^\+([\d]{9,15})$')
        valid_phones = [p for p in phones if phone_regexp.match(p)]
        if not valid_phones:
            raise AmazonSNSValidateFailed("User does not have valid phone numbers")
        return valid_phones

    def send_token(self, user, token):
        phones = user['result'].get(self.ldap_attribute_name, [])
        phones = self.__filter_phones(phones)

        try:
            sns = boto3.client('sns', region_name=self.aws_region)
            for phone in phones:
                sns.publish(
                    PhoneNumber=phone,
                    Message=self.msg_template.format(token),
                    MessageAttributes={
                        'AWS.SNS.SMS.SenderID': {
                            'DataType': 'String',
                            'StringValue': self.sender_id
                        }
                    }
                )
        except Exception as e:
            raise AmazonSNSFailed(f"Cannot send SMS via Amazon SNS: {str(e)}")


class Email:
    def __init__(self, options):
        self.msg_template = options['msg_template']
        self.msg_subject = options['msg_subject']
        self.smtp_user = options['smtp_user']
        self.smtp_pass = options['smtp_pass']
        self.smtp_server_addr = options['smtp_server_addr']
        self.smtp_server_port = options['smtp_server_port']
        self.smtp_server_tls = options['smtp_server_tls']
        self.smtp_from = options.get('smtp_from', self.smtp_user)
        self.ldap_attribute_name = options.get('ldap_attribute_name', 'mail')  # default to 'mail'

    def __filter_emails(self, emails):
        if not emails:
            raise EmailValidateFailed(
                "Missing alternative email. Contact UIS Helpdesk on Ext. 816")
        valid_emails = [email for email in emails if self.__is_valid_email(email)]
        if not valid_emails:
            raise EmailValidateFailed(f"No valid email addresses found")
        return valid_emails

    @staticmethod
    def __is_valid_email(email):
        try:
            validate_email(email)
            return True
        except ValidationError:
            return False

    def send_token(self, user, token):
        result = user.get('result', {})
        raw_emails = result.get(self.ldap_attribute_name, [])

        # Normalize single string to list
        if isinstance(raw_emails, str):
            raw_emails = [raw_emails]

        recipients = self.__filter_emails(raw_emails)

        #Get full name (cn), fallback to UID or "User"
        full_name = result.get('cn', [None])[0] or result.get('uid', ['User'])[0]

        #Format message body and subject
        msg_body = self.msg_template.format(token=token, full_name=full_name)
        subject = self.msg_subject.format(full_name=full_name)
        msg = MIMEText(msg_body)
        msg['Subject'] = subject
        msg['From'] = self.smtp_from
        msg['To'] = ", ".join(recipients)


        try:
            with smtplib.SMTP(self.smtp_server_addr, self.smtp_server_port, timeout=10) as smtp:
                if self.smtp_server_tls:
                    smtp.ehlo()
                    smtp.starttls()
                    smtp.ehlo()
                if self.smtp_user and self.smtp_pass:
                    smtp.login(self.smtp_user, self.smtp_pass)
                smtp.sendmail(msg['From'], recipients, msg.as_string())

            logger.info(f"Sent token to {full_name} <{recipients}>")

        except Exception as e:
            logger.exception("Failed to send email token")
            raise EmailSendFailed(f"Cannot send email: {str(e)}")


class Signal:
    def __init__(self, options):
        self.msg_template = options['msg_template']
        self.sender_number = options['sender_number']
        self.ldap_attribute_name = options.get('ldap_attribute_name', 'telephonenumber')

    def __filter_phones(self, phones):
        phone_regexp = re.compile(r'^\+([\d]{9,15})$')
        valid = [p for p in phones if phone_regexp.match(p)]
        if not valid:
            raise SignalValidateFailed("User does not have valid phone numbers")
        return valid

    def send_token(self, user, token):
        phones = user['result'].get(self.ldap_attribute_name, [])
        phones = self.__filter_phones(phones)

        try:
            for phone in phones:
                proc = subprocess.Popen(
                    [
                        "signal-cli",
                        "-u",
                        self.sender_number,
                        "send",
                        "-m",
                        self.msg_template.format(token),
                        phone
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT
                )
                output, _ = proc.communicate()
                if proc.returncode != 0:
                    raise SignalFailed(output.decode('utf-8'))
        except Exception as e:
            raise SignalFailed(str(e))


class Slack:
    def __init__(self, options):
        self.msg_template = options['msg_template']
        self.slack_hook = options['slack_hook']
        self.slack_username = options['slack_username']
        self.slack_icon_emoji = options['slack_icon_emoji']

    def __filter_login(self, uid):
        if not uid:
            raise SlackValidateFailed("User login not found")
        return uid

    def send_token(self, user, token):
        recipient = self.__filter_login(user['result']['uid'][0])
        msg = self.msg_template.format(token)

        payload = {
            'channel': f'@{recipient}',
            'username': self.slack_username,
            'text': msg,
            'icon_emoji': self.slack_icon_emoji,
            'mrkdwn': 'true'
        }

        try:
            response = requests.post(
                self.slack_hook,
                data=json.dumps(payload),
                headers={'Content-Type': 'application/json'}
            )
            logger.info(f"Slack response status: {response.status_code}")
            if response.status_code != 200:
                raise SlackSendFailed(f"Slack error {response.status_code}:\n{response.text}")
        except Exception as e:
            raise SlackSendFailed(str(e))