Resource Server
===============

Protect users resources, so that only the authorized clients with the
authorized access token can access the given scope resources.

A resource server can be a different server other than the authorization
server. Here is the way to protect your users' resources in Django::

    from authlib.django.oauth2 import ResourceProtector, BearerTokenValidator
    from django.http import JsonResponse

    require_oauth = ResourceProtector()
    require_oauth.register_token_validator(BearerTokenValidator(OAuth2Token))

    @require_oauth('profile')
    def user_profile(request):
        user = request.oauth_token.user
        return JsonResponse(dict(sub=user.pk, username=user.username))

If the resource is not protected by a scope, use ``None``::

    @require_oauth()
    def user_profile(request):
        user = request.oauth_token.user
        return JsonResponse(dict(sub=user.pk, username=user.username))

    # or with None

    @app.route('/user')
    @require_oauth(None)
    def user_profile():
        user = request.oauth_token.user
        return JsonResponse(dict(sub=user.pk, username=user.username))

The decorator ``require_oauth`` will add an ``oauth_token`` property on ``request``,
which is the instance of current in-use Token.

Multiple Scopes
---------------

You can apply multiple scopes to one endpoint in **AND** and **OR** modes.
The default is **AND** mode.

.. code-block:: python

    @require_oauth('profile email', 'AND')
    def user_profile(request):
        user = request.oauth_token.user
        return JsonResponse(dict(sub=user.pk, username=user.username))

It requires the token containing both ``profile`` and ``email`` scope.

.. code-block:: python

    @require_oauth('profile email', 'OR')
    def user_profile(request):
        user = request.oauth_token.user
        return JsonResponse(dict(sub=user.pk, username=user.username))

It requires the token containing either ``profile`` or ``email`` scope.

It is also possible to pass a function as the scope operator. e.g.::

    def scope_operator(token_scopes, resource_scopes):
        # this equals "AND"
        return token_scopes.issuperset(resource_scopes)

    @require_oauth('profile email', scope_operator)
    def user_profile(request):
        user = request.oauth_token.user
        return JsonResponse(dict(sub=user.pk, username=user.username))
