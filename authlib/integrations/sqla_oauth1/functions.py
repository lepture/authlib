def create_query_client_func(session, model_class):
    """Create an ``query_client`` function that can be used in authorization
    server and resource protector.

    :param session: SQLAlchemy session
    :param model_class: Client class
    """
    def query_client(client_id):
        q = session.query(model_class)
        return q.filter_by(client_id=client_id).first()
    return query_client


def create_query_token_func(session, model_class):
    """Create an ``query_token`` function that can be used in
    resource protector.

    :param session: SQLAlchemy session
    :param model_class: TokenCredential class
    """
    def query_token(client_id, oauth_token):
        q = session.query(model_class)
        return q.filter_by(
            client_id=client_id, oauth_token=oauth_token).first()
    return query_token


def register_temporary_credential_hooks(
        authorization_server, session, model_class):
    """Register temporary credential related hooks to authorization server.

    :param authorization_server: AuthorizationServer instance
    :param session: SQLAlchemy session
    :param model_class: TemporaryCredential class
    """

    def create_temporary_credential(token, client_id, redirect_uri):
        item = model_class(
            client_id=client_id,
            oauth_token=token['oauth_token'],
            oauth_token_secret=token['oauth_token_secret'],
            oauth_callback=redirect_uri,
        )
        session.add(item)
        session.commit()
        return item

    def get_temporary_credential(oauth_token):
        q = session.query(model_class).filter_by(oauth_token=oauth_token)
        return q.first()

    def delete_temporary_credential(oauth_token):
        q = session.query(model_class).filter_by(oauth_token=oauth_token)
        q.delete(synchronize_session=False)
        session.commit()

    def create_authorization_verifier(credential, grant_user, verifier):
        credential.set_user_id(grant_user.get_user_id())
        credential.oauth_verifier = verifier
        session.add(credential)
        session.commit()
        return credential

    authorization_server.register_hook(
        'create_temporary_credential', create_temporary_credential)
    authorization_server.register_hook(
        'get_temporary_credential', get_temporary_credential)
    authorization_server.register_hook(
        'delete_temporary_credential', delete_temporary_credential)
    authorization_server.register_hook(
        'create_authorization_verifier', create_authorization_verifier)


def create_exists_nonce_func(session, model_class):
    """Create an ``exists_nonce`` function that can be used in hooks and
    resource protector.

    :param session: SQLAlchemy session
    :param model_class: TimestampNonce class
    """
    def exists_nonce(nonce, timestamp, client_id, oauth_token):
        q = session.query(model_class.nonce).filter_by(
            nonce=nonce,
            timestamp=timestamp,
            client_id=client_id,
        )
        if oauth_token:
            q = q.filter_by(oauth_token=oauth_token)
        rv = q.first()
        if rv:
            return True

        item = model_class(
            nonce=nonce,
            timestamp=timestamp,
            client_id=client_id,
            oauth_token=oauth_token,
        )
        session.add(item)
        session.commit()
        return False
    return exists_nonce


def register_nonce_hooks(authorization_server, session, model_class):
    """Register nonce related hooks to authorization server.

    :param authorization_server: AuthorizationServer instance
    :param session: SQLAlchemy session
    :param model_class: TimestampNonce class
    """
    exists_nonce = create_exists_nonce_func(session, model_class)
    authorization_server.register_hook('exists_nonce', exists_nonce)


def register_token_credential_hooks(
        authorization_server, session, model_class):
    """Register token credential related hooks to authorization server.

    :param authorization_server: AuthorizationServer instance
    :param session: SQLAlchemy session
    :param model_class: TokenCredential class
    """
    def create_token_credential(token, temporary_credential):
        item = model_class(
            oauth_token=token['oauth_token'],
            oauth_token_secret=token['oauth_token_secret'],
            client_id=temporary_credential.get_client_id()
        )
        item.set_user_id(temporary_credential.get_user_id())
        session.add(item)
        session.commit()
        return item

    authorization_server.register_hook(
        'create_token_credential', create_token_credential)


def register_authorization_hooks(
        authorization_server, session,
        token_credential_model,
        temporary_credential_model=None,
        timestamp_nonce_model=None):

    register_token_credential_hooks(
        authorization_server, session, token_credential_model)

    if temporary_credential_model is not None:
        register_temporary_credential_hooks(
            authorization_server, session, temporary_credential_model)

    if timestamp_nonce_model is not None:
        register_nonce_hooks(
            authorization_server, session, timestamp_nonce_model)
