import SessionService from 'ember-simple-auth/services/session';

const session = SessionService.create();

session.trigger('event', { hello: 'world' });
session.authenticate('my-authenticator').then(() => {
    if (session.store) {
        session.store.persist([1, 2, 3]);
    }
});
