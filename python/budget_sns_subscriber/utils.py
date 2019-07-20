import json
import logging

import boto3
from botocore.exceptions import ClientError
from email_validator import EmailNotValidError, validate_email
from flask import current_app

logger = logging.getLogger(__name__)


def valid_email(email):
    """Validate email address.

    :returns: True if everything went well. False otherwise.
    """
    try:
        validate_email(email)
        result = True
    except EmailNotValidError as e:
        logging.error(f"Email not valid: {e}")
        result = False
    return result


def send_email(to_addresses, subject, message_html, **kwargs):
    """A simple function to send an email through AWS SES service.

    Some consideration to have in mind:
        - The message must include at least one recipient email address. The
          recipient address can be a To: address, a CC: address, or a
          BCC: address.
        - Default recipient will be To: addresses.
        - The message may not include more than 50 recipients across the To:
          CC: and BCC: fields.
        - If a recipient email address is invalid (that is, it is not in the
          format UserName@[SubDomain.]Domain.TopLevelDomain ), the entire
          message will be rejected, even if the message contains other
          recipients that are valid.
        - The maximum message size is 10 MB.

    :param to_addresses: list of email addresses.
    :type to_addresses: `list` of `str`.
    :param subject: email subject
    :type subject: `str`
    :param message_html: message as html format.
    :type message_html: `str`
    :param **kwargs: `cc_addresses` and `bcc_addresses` will be the expected
        arguments to be packed up.
    :type **kwargs: `cc_addresses` and `bcc_addresses` are expected to be a list
        of `str`. Each string should have a valid email format.
    :returns: True if success, False if error. Error will be logged as error
        Level.
    :rtype: `bool`
    :raises: If API SendEmail error occurred, the original exception will be
        raised. This can be catched with botocore.exceptions.ClientError.
        For more information about SendEmail errors, please see:
        https://docs.aws.amazon.com/ses/latest/APIReference/API_SendEmail.html
    """
    email_from = current_app.config['NOTIFICATION_EMAIL_ADDRESS']
    ses_region = current_app.config['AWS_SES_REGION']
    ses = boto3.client('ses', region_name=ses_region)
    email_payload = {
        'Source': email_from,
        'Destination': {
            'ToAddresses': to_addresses,
        },
        'Message': {
            'Subject': {
                'Data': subject,
            },
            'Body': {
                'Html': {
                    'Data': message_html,
                    'Charset': 'UTF-8'
                }
            }
        }
    }
    cc_addresses = kwargs.get('cc_addresses')
    bcc_addresses = kwargs.get('bcc_addresses')
    if cc_addresses:
        email_payload['Destination']['CcAddresses'] = cc_addresses
    if bcc_addresses:
        email_payload['Destination']['BccAddresses'] = bcc_addresses
    try:
        ses.send_email(**email_payload)
        result = True
    except ClientError as e:
        raise
    except Exception as e:
        logger.error(e)
        result = False
    return result
