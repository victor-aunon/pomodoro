import json
import requests
from flask import current_app
from flask_babel import _


def translate(text, source_language, dest_language):
    if 'MS_TRANSLATOR_KEY' not in current_app.config or not current_app.config['MS_TRANSLATOR_KEY']:
        return _('Error: the translation service is not configured.')
    auth = {'Ocp-Apim-Subscription-Key': current_app.config['MS_TRANSLATOR_KEY']}
    body = [{'text': text}]
    r = requests.post('https://api-eur.cognitive.microsofttranslator.com/translate?api-version=3.0&from={}&to={}'.format(
                     source_language, dest_language), headers=auth, json=body)
    # 200 is the code for a successful request
    if r.status_code != 200:
        return _('Error: the translation service failed.')
    return json.loads(r.content.decode('utf-8-sig'))