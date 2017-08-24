// Type definitions for ember-simple-auth 1.4
// Project: https://github.com/simplabs/ember-simple-auth
// Definitions by: Dan Freeman <https://github.com/dfreeman>
// Definitions: https://github.com/DefinitelyTyped/DefinitelyTyped
// TypeScript Version: 2.4

declare module 'ember-simple-auth/authenticators/base' {
    import RSVP from 'rsvp';
    import EmberObject from '@ember/object';
    import Evented from '@ember/object/evented';

    /**
     The base class for all authenticators. __This serves as a starting point for
    implementing custom authenticators and must not be used directly.__
    The authenticator authenticates the session. The actual mechanism used to do
    this might, e.g., post a set of credentials to a server and in exchange
    retrieve an access token, initiating authentication against an external
    provider like Facebook, etc. The details depend on the specific authenticator.
    Upon successful authentication, any data that the authenticator receives and
    resolves via the promise returned from the
    {{#crossLink "BaseAuthenticator/authenticate:method"}}{{/crossLink}}
    method is stored in the session and can be accessed via the session service
    to be used by the authorizer (see
    {{#crossLink "BaseAuthorizer/authorize:method"}}{{/crossLink}}) to e.g.,
    authorize outgoing requests.
    The authenticator also decides whether a set of data that was restored from
    the session store (see
    {{#crossLink "BaseStore/restore:method"}}{{/crossLink}}) makes up an
    authenticated session or not.
    __Authenticators for an application are defined in the `app/authenticators`
    directory__, e.g.:
    ```js
    // app/authenticators/oauth2.js
    import OAuth2PasswordGrantAuthenticator from 'ember-simple-auth/authenticators/oauth2-password-grant';
    export default OAuth2PasswordGrantAuthenticator.extend({
        ...
    });
    ```
    and can then be used via the name Ember CLI automatically registers for them
    within the Ember container.
    ```js
    // app/components/login-form.js
    export default Ember.Controller.extend({
        session: Ember.inject.service(),
        actions: {
            authenticate: function() {
                this.get('session').authenticate('authenticator:oauth2');
            }
        }
    });
    ```
    @class BaseAuthenticator
    @module ember-simple-auth/authenticators/base
    @extends Ember.Object
    @uses Ember.Evented
    @public
    */
    export default class BaseAuthenticator extends EmberObject.extend(Evented) {
        /**
        Restores the session from a session data object. __This method is invoked
        by the session either on application startup if session data is restored
        from the session store__ or when properties in the store change due to
        external events (e.g. in another tab) and the new session data needs to be
        validated for whether it constitutes an authenticated session.
        __This method returns a promise. A resolving promise results in the session
        becoming or remaining authenticated.__ Any data the promise resolves with
        will be saved in and accessible via the session service's
        `data.authenticated` property (see
        {{#crossLink "SessionService/data:property"}}{{/crossLink}}). A rejecting
        promise indicates that `data` does not constitute a valid session and will
        result in the session being invalidated or remaining unauthenticated.
        The `BaseAuthenticator`'s implementation always returns a rejecting
        promise. __This method must be overridden in subclasses.__
        @method restore
        @param {Object} data The data to restore the session from
        @return {Ember.RSVP.Promise} A promise that when it resolves results in the session becoming or remaining authenticated
        @public
        */
        restore(data: object): RSVP.Promise<any, any>;

        /**
        Authenticates the session with the specified `args`. These options vary
        depending on the actual authentication mechanism the authenticator
        implements (e.g. a set of credentials or a Facebook account id etc.). __The
        session will invoke this method in order to authenticate itself__ (see
        {{#crossLink "SessionService/authenticate:method"}}{{/crossLink}}).
        __This method returns a promise. A resolving promise will result in the
        session becoming authenticated.__ Any data the promise resolves with will
        be saved in and accessible via the session service's `data.authenticated`
        property (see {{#crossLink "SessionService/data:property"}}{{/crossLink}}).
        A rejecting promise indicates that authentication failed and will result in
        the session remaining unauthenticated.
        The `BaseAuthenticator`'s implementation always returns a rejecting promise
        and thus never authenticates the session. __This method must be overridden
        in subclasses__.
        @method authenticate
        @param {Any} [...args] The arguments that the authenticator requires to authenticate the session
        @return {Ember.RSVP.Promise} A promise that when it resolves results in the session becoming authenticated
        @public
        */
        authenticate(...args: any[]): RSVP.Promise<any, any>;

        /**
        This method is invoked as a callback when the session is invalidated. While
        the session will invalidate itself and clear all authenticated session data,
        it might be necessary for some authenticators to perform additional tasks
        (e.g. invalidating an access token on the server side).
        __This method returns a promise. A resolving promise will result in the
        session becoming unauthenticated.__ A rejecting promise will result in
        invalidation being intercepted and the session remaining authenticated.
        The `BaseAuthenticator`'s implementation always returns a resolving promise
        and thus never intercepts session invalidation. __This method doesn't have
        to be overridden in custom authenticators__ if no actions need to be
        performed on session invalidation.
        @method invalidate
        @param {Object} data The current authenticated session data
        @param {Array} ...args additional arguments as required by the authenticator
        @return {Ember.RSVP.Promise} A promise that when it resolves results in the session being invalidated
        @public
        */
        invalidate(data: object, ...args: any[]): RSVP.Promise<any, any>;
    }
}

declare module 'ember-simple-auth/authenticators/devise' {
    import BaseAuthenticator from 'ember-simple-auth/authenticators/base';

    /**
     Authenticator that works with the Ruby gem
    [devise](https://github.com/plataformatec/devise).
    __As token authentication is not actually part of devise anymore, the server
    needs to implement some customizations__ to work with this authenticator -
    see [this gist](https://gist.github.com/josevalim/fb706b1e933ef01e4fb6).
    @class DeviseAuthenticator
    @module ember-simple-auth/authenticators/devise
    @extends BaseAuthenticator
    @public
    */
    export default class DeviseAuthenticator extends BaseAuthenticator {
        /**
        The endpoint on the server that the authentication request is sent to.
        @property serverTokenEndpoint
        @type String
        @default '/users/sign_in'
        @public
        */
        serverTokenEndpoint: string;

        /**
        The devise resource name. __This will be used in the request and also be
        expected in the server's response.__
        @property resourceName
        @type String
        @default 'user'
        @public
        */
        resourceName: string;

        /**
        The token attribute name. __This will be used in the request and also be
        expected in the server's response.__
        @property tokenAttributeName
        @type String
        @default 'token'
        @public
        */
        tokenAttribute: string;

        /**
        The identification attribute name. __This will be used in the request and
        also be expected in the server's response.__
        @property identificationAttributeName
        @type String
        @default 'email'
        @public
        */
        identificationAttributeName: string;

        /**
        When authentication fails, the rejection callback is provided with the whole
        Fetch API [Response](https://fetch.spec.whatwg.org/#response-class) object
        instead of its responseJSON or responseText.
        This is useful for cases when the backend provides additional context not
        available in the response body.
        @property rejectWithResponse
        @type Boolean
        @default false
        @public
        */
        rejectWithResponse: false;

        /**
        Makes a request to the Devise server using
        [ember-fetch](https://github.com/stefanpenner/ember-fetch).
        @method makeRequest
        @param {Object} data The request data
        @param {Object} options request options that are passed to `fetch`
        @return {Promise} The promise returned by `fetch`
        @protected
        */
        protected makeRequest(data: object, options?: object): Promise<Response>;
    }
}

declare module 'ember-simple-auth/authenticators/oauth2-implicit-grant' {
    import BaseAuthenticator from 'ember-simple-auth/authenticators/base';

    /**
     Authenticator that conforms to OAuth 2
    ([RFC 6749](http://tools.ietf.org/html/rfc6749)), specifically the _"Implicit
    Grant Type"_.
    Use {{#crossLink "OAuth2ImplicitGrantCallbackMixin"}}{{/crossLink}} in your
    OAuth 2.0 redirect route to parse authentication parameters from location
    hash string into an object.
    @class OAuth2ImplicitGrantAuthenticator
    @module ember-simple-auth/authenticators/oauth2-implicit-grant
    @extends BaseAuthenticator
    @public
    */
    export default class OAuth2ImplicitGrantAuthenticator extends BaseAuthenticator {
    }
}

declare module 'ember-simple-auth/authenticators/oauth2-password-grant' {
    import BaseAuthenticator from 'ember-simple-auth/authenticators/base';

    /**
     Authenticator that conforms to OAuth 2
    ([RFC 6749](http://tools.ietf.org/html/rfc6749)), specifically the _"Resource
    Owner Password Credentials Grant Type"_.
    This authenticator also automatically refreshes access tokens (see
    [RFC 6749, section 6](http://tools.ietf.org/html/rfc6749#section-6)) if the
    server supports it.
    @class OAuth2PasswordGrantAuthenticator
    @module ember-simple-auth/authenticators/oauth2-password-grant
    @extends BaseAuthenticator
    @public
    */
    export default class OAuth2PasswordGrantAuthenticator extends BaseAuthenticator {
        /**
        The client_id to be sent to the authentication server (see
        https://tools.ietf.org/html/rfc6749#appendix-A.1). __This should only be
        used for statistics or logging etc. as it cannot actually be trusted since
        it could have been manipulated on the client!__
        @property clientId
        @type String
        @default null
        @public
        */
        clientId: string | null;

        /**
        The endpoint on the server that authentication and token refresh requests
        are sent to.
        @property serverTokenEndpoint
        @type String
        @default '/token'
        @public
        */
        serverTokenEndpoint: string;

        /**
        The endpoint on the server that token revocation requests are sent to. Only
        set this if the server actually supports token revocation. If this is
        `null`, the authenticator will not revoke tokens on session invalidation.
        __If token revocation is enabled but fails, session invalidation will be
        intercepted and the session will remain authenticated (see
        {{#crossLink "OAuth2PasswordGrantAuthenticator/invalidate:method"}}{{/crossLink}}).__
        @property serverTokenRevocationEndpoint
        @type String
        @default null
        @public
        */
        serverTokenRevocationEndpoint: string | null;

        /**
        Sets whether the authenticator automatically refreshes access tokens if the
        server supports it.
        @property refreshAccessTokens
        @type Boolean
        @default true
        @public
        */
        refreshAccessTokens: boolean;

        /**
        The offset time in milliseconds to refresh the access token. This must
        return a random number. This randomization is needed because in case of
        multiple tabs, we need to prevent the tabs from sending refresh token
        request at the same exact moment.
        __When overriding this property, make sure to mark the overridden property
        as volatile so it will actually have a different value each time it is
        accessed.__
        @property tokenRefreshOffset
        @type Integer
        @default a random number between 5 and 10
        @public
        */
        tokenRefreshOffset: number;

        /**
        When authentication fails, the rejection callback is provided with the whole
        Fetch API [Response](https://fetch.spec.whatwg.org/#response-class) object
        instead of its responseJSON or responseText.
        This is useful for cases when the backend provides additional context not
        available in the response body.
        @property rejectWithResponse
        @type Boolean
        @default false
        @public
        */
        rejectWithResponse: false;

        /**
        Makes a request to the OAuth 2.0 server.
        @method makeRequest
        @param {String} url The request URL
        @param {Object} data The request data
        @param {Object} headers Additional headers to send in request
        @return {Promise} A promise that resolves with the response object
        @protected
        */
        protected makeRequest(url: string, data: object, headers: object): Promise<object>;
    }
}

declare module 'ember-simple-auth/authenticators/torii' {
    import BaseAuthenticator from 'ember-simple-auth/authenticators/base';

    /**
     Authenticator that wraps the
    [Torii library](https://github.com/Vestorly/torii) and thus allows to connect
    any external authentication provider that torii defines a provider for.
    In order to use this authenticator, __the application needs to have the
    [torii addon](https://github.com/Vestorly/torii) installed and must inject
    the torii service into the authenticator__:
    ```js
    // app/authenticators/torii.js
    import ToriiAuthenticator from 'ember-simple-auth/authenticators/torii';
    export default ToriiAuthenticator.extend({
    torii: Ember.inject.service()
    });
    ```
    @class ToriiAuthenticator
    @module ember-simple-auth/authenticators/torii
    @extends BaseAuthenticator
    @public
    */
    export default class ToriiAuthenticator extends BaseAuthenticator {
    }
}

declare module 'ember-simple-auth/authorizers/base' {
    import EmberObject from '@ember/object';

    /**
     The base class for all authorizers. __This serves as a starting point for
    implementing custom authorizers and must not be used directly.__
    Authorizers use the session data acquired by an authenticator when
    authenticating the session to construct authorization data that can, e.g., be
    injected into outgoing network requests. Depending on the authorization
    mechanism the authorizer implements, that authorization data might be an HTTP
    header, query string parameters, a cookie, etc.
    __The authorizer has to fit the authenticator__ (see
    {{#crossLink "BaseAuthenticator"}}{{/crossLink}})
    as it can only use data that the authenticator acquires when authenticating
    the session.
    @class BaseAuthorizer
    @module ember-simple-auth/authorizers/base
    @extends Ember.Object
    @public
    */
    export default class BaseAuthorizer extends EmberObject {
        /**
        Authorizes a block of code. This method will be invoked by the session
        service's {{#crossLink "SessionService/authorize:method"}}{{/crossLink}}
        method which will pass the current authenticated session data (see
        {{#crossLink "SessionService/data:property"}}{{/crossLink}}) and a block.
        Depending on the mechanism it implements, the authorizer transforms the
        session data into authorization data and invokes the block with that data.
        `BaseAuthorizer`'s implementation does nothing. __This method must be
        overridden in custom authorizers.__
        @method authorize
        @param {Object} data The current authenticated session data
        @param {Function} block The callback to call with the authorization data
        @public
        */
        authorize(data: object, block: (headerName: string, headerContent: string) => void): void;
    }
}

declare module 'ember-simple-auth/authorizers/devise' {
    import BaseAuthorizer from 'ember-simple-auth/authorizers/base';

    /**
    Authorizer that works with the Ruby gem
    [devise](https://github.com/plataformatec/devise); includes the user's token
    and identification from the session data in the `Authorization` HTTP header,
    e.g.,
    ```
    Authorization: token="234rtgjneroigne4" email="user@domain.tld"
    ```
    __As token authentication is not actually part of devise anymore, the server
    needs to implement some customizations__ to work with this authenticator -
    see [this gist](https://gist.github.com/josevalim/fb706b1e933ef01e4fb6).
    @class DeviseAuthorizer
    @module ember-simple-auth/authorizers/devise
    @extends BaseAuthorizer
    @public
    */
    export default class DeviseAuthorizer extends BaseAuthorizer {
        /**
        The token attribute name.
        @property tokenAttributeName
        @type String
        @default 'token'
        @public
        */
        tokenAttributeName: string;

        /**
        The identification attribute name.
        @property identificationAttributeName
        @type String
        @default 'email'
        @public
        */
        identificationAttributeName: string;
    }
}

declare module 'ember-simple-auth/authorizers/oauth2-bearer' {
    import BaseAuthorizer from 'ember-simple-auth/authorizers/base';

    /**
     Authorizer that conforms to OAuth 2
    ([RFC 6749](http://tools.ietf.org/html/rfc6749)); includes the access token
    from the session data as a bearer token
    ([RFC 6750](http://tools.ietf.org/html/rfc6750)) in the `Authorization`
    header, e.g.:
    ```
    Authorization: Bearer 234rtgjneroigne4
    ```
    @class OAuth2BearerAuthorizer
    @module ember-simple-auth/authorizers/oauth2-bearer
    @extends BaseAuthorizer
    @public
    */
    export default class OAuth2BearerAuthorizer extends BaseAuthorizer {
    }
}

declare module 'ember-simple-auth/mixins/application-route-mixin' {
    import Mixin from '@ember/object/mixin';
    import Route from '@ember/routing/route';
    import SessionService from 'ember-simple-auth/services/session';
    import AuthenticatedRouteMixin from 'ember-simple-auth/mixins/authenticated-route-mixin';

    /**
     The mixin for the application route, __defining methods that are called when
    the session is successfully authenticated (see
    {{#crossLink "SessionService/authenticationSucceeded:event"}}{{/crossLink}})
    or invalidated__ (see
    {{#crossLink "SessionService/invalidationSucceeded:event"}}{{/crossLink}}).
    __Using this mixin is optional.__ The session events can also be handled
    manually, e.g. in an instance initializer:
    ```js
    // app/instance-initializers/session-events.js
    export function initialize(instance) {
    const applicationRoute = instance.container.lookup('route:application');
    const session          = instance.container.lookup('service:session');
        session.on('authenticationSucceeded', function() {
            applicationRoute.transitionTo('index');
        });
        session.on('invalidationSucceeded', function() {
            applicationRoute.transitionTo('bye');
        });
    };
    export default {
    initialize,
        name:  'session-events',
        after: 'ember-simple-auth'
    };
    ```
    __When using the `ApplicationRouteMixin` you need to specify
    `needs: ['service:session']` in the application route's unit test.__
    @class ApplicationRouteMixin
    @module ember-simple-auth/mixins/application-route-mixin
    @extends Ember.Mixin
    @public
    */
    interface ApplicationRouteMixin extends AuthenticatedRouteMixin {
    }

    const ApplicationRouteMixin: Mixin<ApplicationRouteMixin, Route>;
    export default ApplicationRouteMixin;
}

declare module 'ember-simple-auth/mixins/authenticated-route-mixin' {
    import Mixin from '@ember/object/mixin';
    import Route from '@ember/routing/route';
    import SessionService from 'ember-simple-auth/services/session';

    /**
     __This mixin is used to make routes accessible only if the session is
    authenticated.__ It defines a `beforeModel` method that aborts the current
    transition and instead transitions to the
    {{#crossLink "Configuration/authenticationRoute:property"}}{{/crossLink}} if
    the session is not authenticated.
    ```js
    // app/routes/protected.js
    import AuthenticatedRouteMixin from 'ember-simple-auth/mixins/authenticated-route-mixin';
    export default Ember.Route.extend(AuthenticatedRouteMixin);
    ```
    @class AuthenticatedRouteMixin
    @module ember-simple-auth/mixins/authenticated-route-mixin
    @extends Ember.Mixin
    @public
    */
    interface AuthenticatedRouteMixin {
        /**
        The session service.
        @property session
        @readOnly
        @type SessionService
        @public
        */
        readonly session: SessionService;

        /**
        The route to transition to after successful authentication.
        @property routeAfterAuthentication
        @type String
        @default 'index'
        @public
        */
        routeAfterAuthentication: string;

        /**
        This method handles the session's
        {{#crossLink "SessionService/authenticationSucceeded:event"}}{{/crossLink}}
        event. If there is a transition that was previously intercepted by the
        {{#crossLink "AuthenticatedRouteMixin/beforeModel:method"}}
        AuthenticatedRouteMixin's `beforeModel` method{{/crossLink}} it will retry
        it. If there is no such transition, the `ember_simple_auth-redirectTarget`
        cookie will be checked for a url that represents an attemptedTransition
        that was aborted in Fastboot mode, otherwise this action transitions to the
        {{#crossLink "Configuration/routeAfterAuthentication:property"}}{{/crossLink}}.
        @method sessionAuthenticated
        @public
        */
        sessionAuthenticated(): void;

        /**
        This method handles the session's
        {{#crossLink "SessionService/invalidationSucceeded:event"}}{{/crossLink}}
        event. __It reloads the Ember.js application__ by redirecting the browser
        to the application's root URL so that all in-memory data (such as Ember
        Data stores etc.) gets cleared.
        If the Ember.js application will be used in an environment where the users
        don't have direct access to any data stored on the client (e.g.
        [cordova](http://cordova.apache.org)) this action can be overridden to e.g.
        simply transition to the index route.
        @method sessionInvalidated
        @public
        */
        sessionInvalidated(): void;
    }

    const AuthenticatedRouteMixin: Mixin<AuthenticatedRouteMixin, Route>;
    export default AuthenticatedRouteMixin;
}

declare module 'ember-simple-auth/mixins/data-adapter-mixin' {
    import Mixin from '@ember/object/mixin';
    import SessionService from 'ember-simple-auth/services/session';

    /**
     __This mixin can be used to make Ember Data adapters authorize all outgoing
    API requests by injecting a header.__ It works with all authorizers that call
    the authorization callback (see
    {{#crossLink "BaseAuthorizer/authorize:method"}}{{/crossLink}}) with header
    name and header content arguments.
    __The `DataAdapterMixin` will also invalidate the session whenever it
    receives a 401 response for an API request.__
    ```js
    // app/adapters/application.js
    import DS from 'ember-data';
    import DataAdapterMixin from 'ember-simple-auth/mixins/data-adapter-mixin';
    export default DS.JSONAPIAdapter.extend(DataAdapterMixin, {
    authorizer: 'authorizer:application'
    });
    ```
    __The `DataAdapterMixin` requires Ember Data 1.13 or later.__
    @class DataAdapterMixin
    @module ember-simple-auth/mixins/data-adapter-mixin
    @extends Ember.Mixin
    @public
    */
    interface DataAdapterMixin {
        /**
        The session service.
        @property session
        @readOnly
        @type SessionService
        @public
        */
        readonly session: SessionService;

        /**
        The authorizer that is used to authorize API requests. The authorizer has
        to call the authorization callback (see
        {{#crossLink "BaseAuthorizer/authorize:method"}}{{/crossLink}}) with header
        name and header content arguments. __This property must be overridden in
        adapters using this mixin.__
        @property authorizer
        @type String
        @default null
        @public
        */
        authorizer: string | null;

        /**
         The default implementation for handleResponse.
        If the response has a 401 status code it invalidates the session (see
        {{#crossLink "SessionService/invalidate:method"}}{{/crossLink}}).
        Override this method if you want custom invalidation logic for incoming responses.
        @method ensureResponseAuthorized
        @param {Number} status The response status as received from the API
        @param  {Object} headers HTTP headers as received from the API
        @param {Any} payload The response body as received from the API
        @param {Object} requestData the original request information
        */
        ensureResponseAuthorized(status: number, headers: object, payload: any, requestData: object): void;
    }

    // TODO this should be Mixin<DataAdapterMixin, DS.Adapter> once ember-data types are available
    const DataAdapterMixin: Mixin<DataAdapterMixin>;
    export default DataAdapterMixin;
}

declare module 'ember-simple-auth/mixins/oauth2-implicit-grant-callback-route-mixin' {
    import Mixin from '@ember/object/mixin';
    import Route from '@ember/routing/route';
    import SessionService from 'ember-simple-auth/services/session';

    /**
     __This mixin is used in the callback route when using OAuth 2.0 Implicit
    Grant authentication.__ It implements the
    {{#crossLink "OAuth2ImplicitGrantCallbackMixin/activate:method"}}{{/crossLink}}
    method that retrieves and processes authentication parameters, such as
    `access_token`, from the hash parameters provided in the callback URL by
    the authentication server. The parameters are then passed to the
    {{#crossLink "OAuth2ImplicitGrantAuthenticator"}}{{/crossLink}}
    @class OAuth2ImplicitGrantCallbackMixin
    @module ember-simple-auth/mixins/ouath2-implicit-grant-callback-mixin
    @extends Ember.Mixin
    @public
    */
    interface OAuth2ImplicitGrantCallbackRouteMixin {
        /**
         The session service.
        @property session
        @readOnly
        @type SessionService
        @public
        */
        readonly session: SessionService;

        /**
        The authenticator that should be used to authenticate the callback. This
        must be a subclass of the
        {{#crossLink "OAuth2ImplicitGrantAuthenticator"}}{{/crossLink}}
        authenticator.
        @property authenticator
        @type String
        @default null
        @public
        */
        authenticator: string | null;

        /**
        Any error that potentially occurs during authentication will be stored in
        this property.
        @property error
        @type String
        @default null
        @public
        */
        error: string | null;
    }

    const OAuth2ImplicitGrantCallbackRouteMixin: Mixin<OAuth2ImplicitGrantCallbackRouteMixin, Route>;
    export default OAuth2ImplicitGrantCallbackRouteMixin;
}

declare module 'ember-simple-auth/mixins/unauthenticated-route-mixin' {
    import Mixin from '@ember/object/mixin';
    import Route from '@ember/routing/route';
    import SessionService from 'ember-simple-auth/services/session';

    /**
     __This mixin is used to make routes accessible only if the session is
    not authenticated__ (e.g., login and registration routes). It defines a
    `beforeModel` method that aborts the current transition and instead
    transitions to the
    {{#crossLink "Configuration/routeIfAlreadyAuthenticated:property"}}{{/crossLink}}
    if the session is authenticated.
    ```js
    // app/routes/login.js
    import UnauthenticatedRouteMixin from 'ember-simple-auth/mixins/unauthenticated-route-mixin';
    export default Ember.Route.extend(UnauthenticatedRouteMixin);
    ```
    @class UnauthenticatedRouteMixin
    @module ember-simple-auth/mixins/unauthenticated-route-mixin
    @extends Ember.Mixin
    @public
    */
    interface UnauthenticatedRouteMixin {
        /**
        The session service.
        @property session
        @readOnly
        @type SessionService
        @public
        */
        readonly session: SessionService;

        /**
        The route to transition to if a route that implements the
        {{#crossLink "UnauthenticatedRouteMixin"}}{{/crossLink}} is accessed when
        the session is authenticated.
        @property routeIfAlreadyAuthenticated
        @type String
        @default 'index'
        @public
        */
        routeIfAlreadyAuthenticated: string;
    }

    const UnauthenticatedRouteMixin: Mixin<UnauthenticatedRouteMixin, Route>;
    export default UnauthenticatedRouteMixin;
}

declare module 'ember-simple-auth/services/session' {
    import RSVP from 'rsvp';
    import Service from '@ember/service';
    import Evented from '@ember/object/evented';
    import BaseStore from 'ember-simple-auth/session-stores/base';
    import Ember from 'ember';

    /**
     __The session service provides access to the current session as well as
    methods to authenticate it, invalidate it, etc.__ It is the main interface for
    the application to Ember Simple Auth's functionality. It can be injected via
    ```js
    // app/components/login-form.js
    import Ember from 'ember';
    export default Ember.Component.extend({
    session: Ember.inject.service('session')
    });
    ```
    @class SessionService
    @module ember-simple-auth/services/session
    @extends Ember.Service
    @uses Ember.Evented
    @public
    */
    export default class SessionService extends Service.extend(Evented) {
        /**
        Returns whether the session is currently authenticated.
        @property isAuthenticated
        @type Boolean
        @readOnly
        @default false
        @public
        */
        readonly isAuthenticated: boolean;

        /**
        The current session data as a plain object. The
        `authenticated` key holds the session data that the authenticator resolved
        with when the session was authenticated (see
        {{#crossLink "BaseAuthenticator/authenticate:method"}}{{/crossLink}}) and
        that will be cleared when the session is invalidated. This data cannot be
        written. All other session data is writable and will not be cleared when
        the session is invalidated.
        @property data
        @type Object
        @readOnly
        @default { authenticated: {} }
        @public
        */
        readonly data: object;

        /**
        The session store.
        @property store
        @type BaseStore
        @readOnly
        @default null
        @public
        */
        readonly store: BaseStore | null;

        /**
        A previously attempted but intercepted transition (e.g. by the
        {{#crossLink "AuthenticatedRouteMixin"}}{{/crossLink}}). If an attempted
        transition is present, the
        {{#crossLink "ApplicationRouteMixin"}}{{/crossLink}} will retry it when the
        session becomes authenticated (see
        {{#crossLink "ApplicationRouteMixin/sessionAuthenticated:method"}}{{/crossLink}}).
        @property attemptedTransition
        @type Transition
        @default null
        @public
        */
        attemptedTransition: object /* Transition seems not to be public */ | null;

        /**
        __Authenticates the session with an `authenticator`__ and appropriate
        arguments. The authenticator implements the actual steps necessary to
        authenticate the session (see
        {{#crossLink "BaseAuthenticator/authenticate:method"}}{{/crossLink}}) and
        returns a promise after doing so. The session handles the returned promise
        and when it resolves becomes authenticated, otherwise remains
        unauthenticated. All data the authenticator resolves with will be
        accessible via the
        {{#crossLink "SessionService/data:property"}}session data's{{/crossLink}}
        `authenticated` property.
        __This method returns a promise. A resolving promise indicates that the
        session was successfully authenticated__ while a rejecting promise
        indicates that authentication failed and the session remains
        unauthenticated. The promise does not resolve with a value; instead, the
        data returned from the authenticator is available via the
        {{#crossLink "SessionService/data:property"}}{{/crossLink}} property.
        When authentication succeeds this will trigger the
        {{#crossLink "SessionService/authenticationSucceeded:event"}}{{/crossLink}}
        event.
        @method authenticate
        @param {String} authenticator The authenticator to use to authenticate the session
        @param {Any} [...args] The arguments to pass to the authenticator; depending on the type of authenticator these might be a set of credentials, a Facebook OAuth Token, etc.
        @return {Ember.RSVP.Promise} A promise that resolves when the session was authenticated successfully and rejects otherwise
        @public
        */
        authenticate(authenticator: string, ...args: any[]): RSVP.Promise<any, any>;

        /**
        __Invalidates the session with the authenticator it is currently
        authenticated with__ (see
        {{#crossLink "SessionService/authenticate:method"}}{{/crossLink}}). This
        invokes the authenticator's
        {{#crossLink "BaseAuthenticator/invalidate:method"}}{{/crossLink}} method
        and handles the returned promise accordingly.
        This method returns a promise. A resolving promise indicates that the
        session was successfully invalidated while a rejecting promise indicates
        that invalidation failed and the session remains authenticated. Once the
        session is successfully invalidated it clears all of its authenticated data
        (see {{#crossLink "SessionService/data:property"}}{{/crossLink}}).
        When invalidation succeeds this will trigger the
        {{#crossLink "SessionService/invalidationSucceeded:event"}}{{/crossLink}}
        event.
        @method invalidate
        @param {Array} ...args arguments that will be passed to the authenticator
        @return {Ember.RSVP.Promise} A promise that resolves when the session was invalidated successfully and rejects otherwise
        @public
        */
        invalidate(...args: any[]): RSVP.Promise<any, any>;

        /**
        Authorizes a block of code with an authorizer (see
        {{#crossLink "BaseAuthorizer/authorize:method"}}{{/crossLink}}) if the
        session is authenticated. If the session is not currently authenticated
        this method does nothing.
        ```js
        this.get('session').authorize('authorizer:oauth2-bearer', (headerName, headerValue) => {
            xhr.setRequestHeader(headerName, headerValue);
        });
        ```
        @method authorize
        @param {String} authorizer The authorizer to authorize the block with
        @param {Function} block The block of code to call with the authorization data generated by the authorizer
        @public
        */
        authorize(authorizer: string, block: (headerName: string, headerContent: string) => void): void;
    }
}

declare module 'ember-simple-auth/session-stores/adaptive' {
    import BaseStore from 'ember-simple-auth/session-stores/base';

    /**
     Session store that persists data in the browser's `localStorage` (see
    {{#crossLink "LocalStorageStore"}}{{/crossLink}}) if that is available or in
    a cookie (see {{#crossLink "CookieStore"}}{{/crossLink}}) if it is not.
    __This is the default store that Ember Simple Auth will use when the
    application doesn't define a custom store.__
    __This session store does not work with FastBoot. In order to use Ember
    Simple Auth with FastBoot, configure the
    {{#crossLink "CookieStore"}}{{/crossLink}} as the application's session
    store.__
    @class AdaptiveStore
    @module ember-simple-auth/session-stores/adaptive
    @extends BaseStore
    @public
    */
    export default class AdaptiveStore extends BaseStore {
        /**
        The `localStorage` key the store persists data in if `localStorage` is
        available.
        @property localStorageKey
        @type String
        @default 'ember_simple_auth-session'
        @public
        */
        localStorageKey: string;

        /**
        The domain to use for the cookie if `localStorage` is not available, e.g.,
        "example.com", ".example.com" (which includes all subdomains) or
        "subdomain.example.com". If not explicitly set, the cookie domain defaults
        to the domain the session was authenticated on.
        @property cookieDomain
        @type String
        @default null
        @public
        */
        cookieDomain: string | null;

        /**
        The name of the cookie to use if `localStorage` is not available.
        @property cookieName
        @type String
        @default ember_simple_auth-session
        @public
        */
        cookieName: string;

        /**
        The path to use for the cookie, e.g., "/", "/something".
        @property cookiePath
        @type String
        @default '/'
        @public
        */
        cookiePath: string;

        /**
        The expiration time for the cookie in seconds if `localStorage` is not
        available. A value of `null` will make the cookie a session cookie that
        expires and gets deleted when the browser is closed.
        @property cookieExpirationTime
        @default null
        @type Integer
        @public
        */
        cookieExpirationTime: number | null;
    }
}

declare module 'ember-simple-auth/session-stores/base' {
    import RSVP from 'rsvp';
    import EmberObject from '@ember/object';
    import Evented from '@ember/object/evented';

    /**
    The base class for all session stores. __This serves as a starting point for
    implementing custom session stores and must not be used directly.__
    Session Stores persist the session's state so that it survives a page reload
    and is synchronized across multiple tabs or windows of the same application.
    @class BaseStore
    @module ember-simple-auth/session-stores/base
    @extends Ember.Object
    @uses Ember.Evented
    @public
    */
    export default class BaseStore extends EmberObject.extend(Evented) {
        /**
        Persists the `data`. This replaces all currently stored data.
        `BaseStores`'s implementation always returns a rejecting promise. __This
        method must be overridden in subclasses__.
        @method persist
        @param {Object} data The data to persist
        @return {Ember.RSVP.Promise} A promise that resolves when the data has successfully been persisted and rejects otherwise.
        @public
        */
        persist(data: object): RSVP.Promise<any, any>;

        /**
        Returns all data currently stored as a plain object.
        `BaseStores`'s implementation always returns a rejecting promise. __This
        method must be overridden in subclasses__.
        @method restore
        @return {Ember.RSVP.Promise} A promise that resolves with the data currently persisted in the store when the data has been restored successfully and rejects otherwise.
        @public
        */
        restore(): RSVP.Promise<any, any>;

        /**
        Clears the store.
        `BaseStores`'s implementation always returns a rejecting promise. __This
        method must be overridden in subclasses__.
        @method clear
        @return {Ember.RSVP.Promise} A promise that resolves when the store has been cleared successfully and rejects otherwise.
        @public
        */
        clear(): RSVP.Promise<any, any>;
    }
}

declare module 'ember-simple-auth/session-stores/cookie' {
    import BaseStore from 'ember-simple-auth/session-stores/base';

    /**
     Session store that persists data in a cookie.
    By default the cookie session store uses a session cookie that expires and is
    deleted when the browser is closed. The cookie expiration period can be
    configured by setting the
    {{#crossLink "CookieStore/cookieExpirationTime:property"}}{{/crossLink}}
    property. This can be used to implement "remember me" functionality that will
    either store the session persistently or in a session cookie depending on
    whether the user opted in or not:
    ```js
    // app/controllers/login.js
    export default Ember.Controller.extend({
    rememberMe: false,
    _rememberMeChanged: Ember.observer('rememberMe', function() {
        const expirationTime = this.get('rememberMe') ? (14 * 24 * 60 * 60) : null;
        this.set('session.store.cookieExpirationTime', expirationTime);
    }
    });
    ```
    __Applications that use FastBoot must use this session store by defining the
    application session store like this:__
    ```js
    // app/session-stores/application.js
    import CookieStore from 'ember-simple-auth/session-stores/cookie';
    export default CookieStore.extend();
    ```
    @class CookieStore
    @module ember-simple-auth/session-stores/cookie
    @extends BaseStore
    @public
    */
    export default class CookieStore extends BaseStore {
        /**
        The domain to use for the cookie, e.g., "example.com", ".example.com"
        (which includes all subdomains) or "subdomain.example.com". If not
        explicitly set, the cookie domain defaults to the domain the session was
        authenticated on.
        @property cookieDomain
        @type String
        @default null
        @public
        */
        cookieDomain: string | null;

        /**
        The name of the cookie.
        @property cookieName
        @type String
        @default ember_simple_auth-session
        @public
        */
        cookieName: string;

        /**
        The path to use for the cookie, e.g., "/", "/something".
        @property cookiePath
        @type String
        @default '/'
        @public
        */
        cookiePath: string;

        /**
        The expiration time for the cookie in seconds. A value of `null` will make
        the cookie a session cookie that expires and gets deleted when the browser
        is closed.
        The recommended minimum value is 90 seconds. If your value is less than
        that, the cookie may expire before its expiration time is extended
        (expiration time is extended every 60 seconds).
        @property cookieExpirationTime
        @default null
        @type Integer
        @public
        */
        cookieExpirationTime: number | null;
    }
}

declare module 'ember-simple-auth/session-stores/ephemeral' {
    import BaseStore from 'ember-simple-auth/session-stores/base';

    /**
     Session store that __persists data in memory and thus is not actually
    persistent__. It does also not synchronize the session's state across
    multiple tabs or windows as those cannot share memory. __This store is mainly
    useful for testing and will automatically be used when running tests.__
    @class EphemeralStore
    @module ember-simple-auth/session-stores/ephemeral
    @extends BaseStore
    @public
    */
    export default class EphemeralStore extends BaseStore {
    }
}

declare module 'ember-simple-auth/session-stores/local-storage' {
    import BaseStore from 'ember-simple-auth/session-stores/base';

    /**
     Session store that persists data in the browser's `localStorage`.
    __`localStorage` is not available in Safari when running in private mode. In
    general it is better to use the
    {{#crossLink "AdaptiveStore"}}{{/crossLink}} that automatically falls back to
    the {{#crossLink "CookieStore"}}{{/crossLink}} when `localStorage` is not
    available.__
    __This session store does not work with FastBoot. In order to use Ember
    Simple Auth with FastBoot, configure the
    {{#crossLink "CookieStore"}}{{/crossLink}} as the application's session
    store.__
    @class LocalStorageStore
    @module ember-simple-auth/session-stores/local-storage
    @extends BaseStore
    @public
    */
    export default class LocalStorageStore extends BaseStore {
        /**
        The `localStorage` key the store persists data in.
        @property key
        @type String
        @default 'ember_simple_auth-session'
        @public
        */
        key: string;
    }
}

declare module 'ember-simple-auth/session-stores/session-storage' {
    import BaseStore from 'ember-simple-auth/session-stores/base';

    /**
     Session store that persists data in the browser's `sessionStorage`.
    __`sessionStorage` is not available in Safari when running in private mode.__
    __This session store does not work with FastBoot. In order to use Ember
    Simple Auth with FastBoot, configure the
    {{#crossLink "CookieStore"}}{{/crossLink}} as the application's session
    store.__
    @class SessionStorageStore
    @module ember-simple-auth/session-stores/session-storage
    @extends BaseStore
    @public
    */
    export default class SessionStorageStore extends BaseStore {
        /**
        The `sessionStorage` key the store persists data in.
        @property key
        @type String
        @default 'ember_simple_auth-session'
        @public
        */
        key: string;
    }
}
