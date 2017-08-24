import BaseAuthenticator from 'ember-simple-auth/authenticators/base';

const authenticator = BaseAuthenticator.create();
authenticator.restore({ foo: 'bar' }).then(() => 'ok');
authenticator.invalidate({ baz: 'qux' }).then(() => 'done');
