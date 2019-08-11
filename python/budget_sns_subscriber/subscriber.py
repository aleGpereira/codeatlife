import logging

from botocore.exceptions import ClientError
from flask import Blueprint, jsonify, request

from .app import app
from .decorators import (budget_subscriber, needs_sns_notification_auth,
                         sns_subscriber)
from .models import Budget, User
from .utils import send_email, valid_email

EMAIL_USER_KEY = 'Budget Name:'
logger = logging.getLogger(__name__)


def get_email_from_budget_message(sns_message):
    """Extracts user email from SNS notification sent by budget.

    :param sns_message: message data
    :type sns_message: `dict`
    :returns: User email. Empty if wasn't able to extract the email.
    :rtype: str
    """
    user_email = ''
    message = sns_message.get('Message')
    budget_index = message.index(EMAIL_USER_KEY)
    budget_end = message.index('\n', budget_index)
    user_email = message[budget_index + len(EMAIL_USER_KEY):budget_end].strip()
    return user_email


def process_notification(message_data):
    """Search all neccessary user information to build the notification.

    Collects user information to use in notification message. Available fields
    in the response will be:
        - user_email
        - user_name
        - threshold
        - budget_amount

    :param message_data: [description]
    :type message_data: [type]
    :return: user information summary. `None` if process fail.
    :rtype: `dict`
    """
    user_email = get_email_from_budget_message(message_data)
    if not user_email:
        return None
    
    user = User.query.filter_by(email=user_email).first()
    user_budget = Budget.query.filter_by(user_id=user.id).first()

    result = {
        'user_email': user_email,
        'user_name': user.name,
        'threshold': user_budget.threshold,
        'budget_amount': user_budget.amount,
    }

    return result


@app.route('/budget-subscriber', methods=['POST'])
@needs_sns_notification_auth
@sns_subscriber
@budget_subscriber
def notify_threshold():
    """Notify to user his quota threshold has been reached.

    Subscription confirmation and aws auth are automatically handled.
    """
    json_data = request.get_json(force=True)
    user_summary = process_notification(json_data)
    if not user_summary:
        error_msg = "Not able to process the sns notification."
        logger.error(error_msg)
        return jsonify({'message': error_msg}), 400

    user_email = user_summary.get('user_email')
    user_name = user_summary.get('user_name')
    threshold = user_summary.get('threshold')
    amount = user_summary.get('quota_amount')

    subject = f"Cost control alert - {threshold}% warning threshold exceeded"
    body = (f"Hi {user_name},<br/><br/>You have exceeded {threshold}% of the ${amount} authorized for the current month. "
                  )
    message_html = f'{body}'
    try:
        sent = send_email([user_email], subject, message_html)
    except ClientError as e:
        error_code = e.response.get('Error').get('Code')
        error_message = f"notification email to user failed: {error_code}"
        logger.error(error_message)
        return jsonify({'message': error_message}), 409

    if not sent:
        error_message = f"Unexpected error trying to send notification to user."
        logger.error(error_message)
        return jsonify({'message': error_message}), 500

    return jsonify({'message': "success"})
