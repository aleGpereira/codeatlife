import logging
from base64 import b64decode
from functools import wraps
from urllib.parse import urlparse
from urllib.request import urlopen

import boto3
from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from flask import jsonify, request

logger = logging.getLogger(__name__)


SNS_MESSAGE_HEADER_TYPE = 'x-amz-sns-message-type'
SUBCRIPTION_TYPE = 'SubscriptionConfirmation'
SUBCRIPTION_FORMAT = ["Message", "MessageId", "SubscribeURL", "Timestamp", "Token", "TopicArn", "Type"]
NOTIFICATION_TYPE = 'Notification'
NOTIFICATION_FORMAT = ["Message", "MessageId", "Subject", "Timestamp", "TopicArn", "Type"]


def _message_builder(message, format):
    """Builds the canonical message to be verified.

    Sorts the fields as a requirement from AWS.

    :param message: Parsed body of the response
    :type message: `dict`
    :param format: List of the fields that need to go into the message
    :type format: `list`
    :returns: canonical message
    :rtype: `str`
    """
    m = ""

    for field in sorted(format):
        try:
            m += field + "\n" + message[field] + "\n"
        except KeyError as e:
            # Build with what you have
            pass

    return str(m)


def needs_sns_notification_auth(f):
    """Endpoint Decorator to check authenticity for AWS SNS notifications.

    If message origin verification is needed this will do the necessary work.
    AWS documentation details the steps necessary in order to perform this
    process successfully. For more information please see:
    https://docs.aws.amazon.com/sns/latest/dg/SendMessageToHttp.verify.signature.html
    """

    @wraps(f)
    def verify_aws_origin(*args, **kwargs):
        if request.headers.get(SNS_MESSAGE_HEADER_TYPE) == SUBCRIPTION_TYPE:
            msg_format = SUBCRIPTION_FORMAT
        elif request.headers.get(SNS_MESSAGE_HEADER_TYPE) == NOTIFICATION_TYPE:
            msg_format = NOTIFICATION_FORMAT
        else:
            logger.error("Message not valid")
            return jsonify({'message': "Not valid"}), 401
        try:
            message_json = request.get_json(force=True)  # Notification will come without Content-type header
            decoded_signature = b64decode(message_json.get("Signature"))
            canonical_message = _message_builder(message_json, msg_format)
            amazon_url = message_json.get("SigningCertURL")
            if not urlparse(amazon_url).hostname.endswith('.amazonaws.com'):
                return jsonify({'message': "Not authorized"}), 403
            cert_content = urlopen(amazon_url).read()
            cert = x509.load_pem_x509_certificate(cert_content, default_backend())
            pubkey = cert.public_key()
            pubkey.verify(
                decoded_signature,
                canonical_message.encode(),
                padding.PKCS1v15(),
                hashes.SHA1()
            )
        except InvalidSignature as e:
            logger.error(e)
            return jsonify({'message': "Not authorized"}), 403
        except Exception as e:
            logger.error(e)
            error_msg = "Couldn't authenticate sns notification."
            return jsonify({'message': error_msg}), 500

        return f(*args, **kwargs)
    return verify_aws_origin


def sns_subscriber(f):
    """Endpoint Decorator to handle SNS subcription.

    Sends a signal to AWS to confirm topic subscription.
    Http/https endpoints that will subscribe to SNS topics needs to confirm
    the subscription. This function executes all necessary steps to have success
    in this process. For more information, please see:
    https://docs.aws.amazon.com/sns/latest/dg/sns-http-https-endpoint-as-subscriber.html#SendMessageToHttp.prepare

    Possible scenarios are:
        - It assumes that messages is valid and origin is AWS.
        - If notification is not subscription type, continues execution.
        - If confirmation is successful, returns a message and 200 code.
        - If confirmation failed against AWS, returns a message and 409 code.
        - If confirmation has internal errors, returns a message and 500 code.

    """
    @wraps(f)
    def confirm_subscription(*args, **kwargs):
        if request.headers.get(SNS_MESSAGE_HEADER_TYPE) == SUBCRIPTION_TYPE:
            client = boto3.client('sns')
            json_data = request.get_json(force=True)  # Notification will come without Content-type header
            topic_arn = json_data.get('TopicArn')
            token = json_data.get('Token')
            try:
                response = client.confirm_subscription(
                    TopicArn=topic_arn,
                    Token=token
                )
            except ClientError as e:
                code = e.response.get('Error').get('Code')
                failed_msg = f"Subscription failed: {code}"
                logger.error(failed_msg)
                return jsonify({'message': failed_msg}), 409
            except Exception as e:
                logger.error(e)
                error_msg = f"Couldn't not process subscription for {request.endpoint} to {topic_arn}"
                logger.error(error_msg)
                return jsonify({'message': error_msg}), 500

            return jsonify({'message': success_msg})

        return f(*args, **kwargs)

    return confirm_subscription


def budget_subscriber(f):
    """Endpoint Decorator to handle Budget subcription to SNS.

    Receives the confirmation message from Budget and returns a successful
    response.
    """

    @wraps(f)
    def confirm_subscription(*args, **kwargs):
        if request.headers.get(SNS_MESSAGE_HEADER_TYPE) == NOTIFICATION_TYPE:
            json_data = request.get_json(force=True)
            message_subject = json_data.get('Subject')
            message = json_data.get('Message')
            topic_arn = json_data.get('TopicArn')
            if message_subject == 'SNS Topic Verified!':
                success_msg = f"Successfully subscribed to budget"
                return jsonify({'message': success_msg})

        return f(*args, **kwargs)

    return confirm_subscription
