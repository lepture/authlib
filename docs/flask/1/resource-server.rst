Resource Servers
================

Protect users resources, so that only the authorized clients with the
authorized access token can access the given scope resources.

A resource server can be a different server other than the authorization
server. Here is the way to protect your users' resources::

    from flask import jsonify
    from authlib.flask.oauth1 import ResourceProtector, current_credential
    from authlib.flask.oauth1.cache import create_exists_nonce_func
    from authlib.flask.oauth1.sqla import (
        create_query_client_func,
        create_query_token_func
    )

    query_client = create_query_client_func(db.session, Client)
    query_token = create_query_token_func(db.session, TokenCredential)
    exists_nonce = create_exists_nonce_func(cache)
    # OR: authlib.flask.oauth1.sqla.create_exists_nonce_func

    require_oauth = ResourceProtector(
        app, query_client=query_client,
        query_token=query_token,
        exists_nonce=exists_nonce,
    )
    # or initialize it lazily
    require_oauth = ResourceProtector()
    require_oauth.init_app(
        app,
        query_client=query_client,
        query_token=query_token,
        exists_nonce=exists_nonce,
    )

    @app.route('/user')
    @require_oauth()
    def user_profile():
        user = current_credential.user
        return jsonify(user)

The ``current_credential`` is a proxy to the Token model you have defined above.
Since there is a ``user`` relationship on the Token model, we can access this
``user`` with ``current_credential.user``.


MethodView & Flask-Restful
--------------------------

You can also use the ``require_oauth`` decorator in ``flask.views.MethodView``
and ``flask_restful.Resource``::

    from flask.views import MethodView

    class UserAPI(MethodView):
        decorators = [require_oauth()]


    from flask_restful import Resource

    class UserAPI(Resource):
        method_decorators = [require_oauth()]

