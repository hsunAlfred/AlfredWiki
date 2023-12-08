import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
import hashlib
import os
import json
import requests

from AlfredWiki.settings import GOOGLE_SERECT, GOOGLE_SCOPES, GOOGLE_REDIRECT_URI, API_SERVICE_NAME, API_VERSION


def startValid():
    # https://developers.google.com/identity/protocols/oauth2/scopes
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        GOOGLE_SERECT,
        scopes=GOOGLE_SCOPES
    )

    # same as set in gcp
    flow.redirect_uri = GOOGLE_REDIRECT_URI

    # Generate URL for request to Google's OAuth 2.0 server.
    # Use kwargs to set optional request parameters.
    state = hashlib.sha256(os.urandom(1024)).hexdigest()

    authorization_url, state = flow.authorization_url(
        # Enable offline access so that you can refresh an access token without
        # re-prompting the user for permission. Recommended for web server apps.
        access_type='offline',
        # Enable incremental authorization. Recommended as a best practice.
        include_granted_scopes='true',
        state=state
    )

    infos = {
        "authorization_url": authorization_url,
        "state": state
    }

    return infos


def credentials_to_dict_str(credentials):
    return json.dumps({
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    })


def callbackHandler(state, authorization_response):
    print(state)
    print(authorization_response)
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        GOOGLE_SERECT,
        scopes=GOOGLE_SCOPES,
        state=state
    )
    flow.redirect_uri = GOOGLE_REDIRECT_URI

    flow.fetch_token(authorization_response=authorization_response)

    credentials = flow.credentials

    return credentials_to_dict_str(credentials)


def testSession(credentials):
    # Load credentials from the session.
    credentials = google.oauth2.credentials.Credentials(
        **json.loads(credentials))

    datas = googleapiclient.discovery.build(
        API_SERVICE_NAME, API_VERSION, credentials=credentials
    )

    userInfos = datas.userinfo().get().execute()

    # Save credentials back to session in case access token was refreshed.
    # ACTION ITEM: In a production app, you likely want to save these
    #              credentials in a persistent database instead.
    credentials = credentials_to_dict_str(credentials)

    infos = {
        "credentials": credentials,
        "userInfos": userInfos
    }

    return infos


def revokeAccess(credentials):
    credentials = google.oauth2.credentials.Credentials(
        **json.loads(credentials))

    revoke = requests.post(
        'https://oauth2.googleapis.com/revoke',
        params={
            'token': credentials.token
        },
        headers={
            'content-type': 'application/x-www-form-urlencoded'
        }
    )

    status_code = getattr(revoke, 'status_code')
    if status_code == 200:
        return 'Credentials successfully revoked.<a href="/google/clear/">clear</a>'
    else:
        return 'An error occurred.'
